# Intelligent Brute Force Detection
I've put a lot of time into normalizing brute force behavior from my time with static authentication failure alerts to create what some vendors would label as 'magic'.
## The Requirements
This requires two sets of data. The data focuses on assets and not users. Assets can launch attacks against multiple users and are generally the threat on the local network.
- One set of data revolves around the ***relative past 60 minutes***. This gives us our current access threat landscape.
- One set of data calculating an ***hourly average and standard deviaton over the past 30 days*** in the environment.
## The SPL for the relative now data set
| tstats summariesonly=1 allow_old_summaries=1 values(sourcetype) as sourcetype values(Authentication.user) as user count from datamodel=Authentication.Authentication where 
(Authentication.action="success" OR Authentication.action="failure")

>This brings in all authentication data configured in the datamodels with the fields normalized to be uniform across all access datasets.

Authentication.user!="*$" Authentication.user!="unknown" NOT Authentication.signature="Kerberos pre-authentication failed*"

>I ignore system user accounts, data failures as 'unknown', and a common failure in kerberos for stale logon activity because nobody leaves work for the day with their session still active. Ever.
NOT (Authentication.src="192.168.0.*")
>This is an example of how to exclude a guest network by IPs. You could also use Authentication.src="192.168.0.0/24" instead of the wildcards. Hostnames for threat sources are also usable, Authentication.src="dudes-macbook-pro.local"

by Authentication.src Authentication.action Authentication.user _time span=1s
>This is the line that aggregates all the authentication event data by every unique src, action, user, and epoch second. Doing this granular of a data output allows for the next stanza's logic.

| eval success=if(match('Authentication.action', "success"), "1", "0")</br>
| eval failure=if(match('Authentication.action', "failure"), "1", "0")</br>
| stats sum(failure) as failure_count sum(success) as success_count values(sourcetype) as orig_sourcetype values(user) as user dc(Authentication.user) as user_count count as total_count by Authentication.src</br>
| table _time Authentication.src total_count, success_count, failure_count user user_count orig_sourcetype</br>
| where failure_count>success_count
>Here I inject one of the most common pain points for tuning. The first line gives a numerical value of 1 for every successful authentication event by src user and second.
>The second line does the inverse. It gives a numerical value of 1 for every failure per user src and second.
>The benefit? The third line. Now we can do math on the outcomes of authentications on top of the pure count of attempts made. Not only can we do math, which is accomplished on the 3rd line, we can make an early decision.
>The fourth line outputs the data into a logical array for later manipulation and decision making where the focus is unique src or assets. The threat source as mentioned before.
>The fifth line is the first decision point. We immediately get rid of false positives from servers that manage a high load of authentication events. LDAP has no concept of x-forward-for like web traffic, so aggregators easily look like attackers.
>With the fifth line, we focus on src or assets that fail more than succeed. By removing situations where there are a high amount of failures but higher amounts of successes, we drop all assets visibile to the network that manage and aggregate authenticaiton.

| eval signature=mvjoin(signature," , ")
>Simple formatting on the usage of the values SPL term to make it human readable instead of a running string of text.

| eval PasswordsPerSecond=round(count/60/60,1)
>Calculate an assumed passwords per second by src/Asset purely on the count of events which were aggregated by second initially.

| lookup Dynamic_Thresholds.csv Authentication.src OUTPUTNEW overall_threshold, overall_std, failures_by_src, std_by_src
>This is where we pull in the second dataset. For each unique Authentication.src/Asset there is a 30 day threshold, standard deviation, failure count, and overall standard deviation across all assets.

| eval upperBound=(failures_by_src+(std_by_src\*6)), OverallUpperBound=(overall_threshold+(overall_std\*2))
>This is where you have the control to tune the math to your results. Normally I ould use quartiles, but the amount of authentication data found on corporate networks can be too large for search time completion and performance.
>I will post a quartile example in this repo.

| where failure_count > upperBound AND failure_count > OverallUpperBound
>Here the decision is made against the dataset and parameters to filter the data down to it's simplest form. 

| mvexpand user</br>
| eval user=mvindex(split(user, "@"), 0)
> for each set of results, expand the user field and remove domains in the second line. Think of the second line like the linux command cut. In this instance "cut -d @ -f 0 user".

| eval date=strftime(_time,"%Y-%m-%d")
>SPL for turning epoch time into human readable time. Thanks to the community posts that made this incredibly easy to find, forget, and find again on many occassions.

| rename Authentication.* as *
>I had to laugh when this worked, but it simply stripped all fields of the prepended "Authentication.", another instance of linux cut.

| stats values(failure_count) as failure_count values(success_count) as success_count values(orig_sourcetype) as orig_sourcetype values(user) as user values(user_count) as user_count values(total_count) as "count" values(std_by_src) as std_by_src values(upperBound) as upperBound values(OverallUpperBound) as OverallUpperBound values(PasswordsPerSecond) as PasswordsPerSecond values(date) as date values(failures_by_src) as failures_by_src values(overall_std) as overall_std values(overall_threshold) as overall_threshold by src
>The final line formats and outputs all of the data used in the calculation, all of the users in the attack, and aggregates it against each unique src/Asset. Internal to the network, a single asset is your first indicator of lateral movement.
##Dataset 2, hourly averages and deviations over 3 days
####We ONLY care about failures here and do not need user stats. Otherwise, this should look almost identical to the first part of the relative now hourly search, outside of the math. I recommend updating this once a day with fresh data to keep up with the changing environment. 
| tstats summariesonly=1 allow_old_summaries=1 values(sourcetype) as sourcetype values(Authentication.user) as user dc(Authentication.user) as user_count count from datamodel=Authentication.Authentication where Authentication.action="failure" Authentication.user!="*$" NOT Authentication.src="unknown" by Authentication.action Authentication.src _time span=1h
>Building out our initial dataset of src/Asset failure events. The last "span=1h" is SPL for blocking the dataset into 60 minute window of results that can repeat with different data in future windows.

| eventstats avg(count) as overall_threshold stdev(count) as overall_std</br>
| stats avg(count) as failures_by_src stdev(count) as std_by_src by Authentication.action, Authentication.src, overall_threshold,  overall_std, sourcetype
>Eventstats builds the raw data per hour for the failure counts across all src/Assets. The new fields are added to each line of the dataset.
>The stats line does the same thing, but for each unique src with the new fields created by the eventstats line. If you do not call out the eventstats fields here, they will be lost in the either.

| eval std_by_src = if(std_by_src=0.0,overall_std,std_by_src) 
> Here we define a minimum baseline when a 0 or new src is found.

| eval failures_by_src = round(failures_by_src, 1)</br>
| eval std_by_src = round(std_by_src, 1)</br>
| eval overall_threshold = round(overall_threshold,1)</br>
| eval overall_std = round(overall_std,1)</br>
> These round the results to exclude decimal points.

| rename "All_Traffic.*" as *
> The field rename *magic* of wildcards. There is a Splunk macro that does the same thing, drop_dm_object(All_Traffic) or something close to that. You can search for it in Advanced Search.

| outputlookup Dynamic_Thresholds.csv
> This last line will write out the entire dataset into a static table stored on the search head for later use. It is called in the hourly search in line 40 of this code, where it brings the data from the 30 day search quickly into the hourly search as it exists in a static csv file.
