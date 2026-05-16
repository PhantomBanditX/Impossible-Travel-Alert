# 🚨 Incident Report: (Potential Impossible Travel) 
<img width="1000" alt="Image" src="https://github.com/user-attachments/assets/532a45d8-a6c2-4ef5-a5f7-07fda7c9828a" />

## 📝 **Explanation**  
Corporations often have strict policies prohibiting:  
- 🌍 Logging in from multiple geographic regions outside designated areas.  
- 🔄 Account sharing (a standard security measure).  
- 🛡️ Using non-corporate VPNs.  

This scenario detects unusual activity, such as logins from **multiple geographic regions** within a short time frame.  

Whenever a user logs into Azure or authenticates with their main Azure account, logs are created in the **"SigninLogs"** table and forwarded to the **Log Analytics workspace** used by Microsoft Sentinel (our SIEM).  

### **Detection Objective:**  
Trigger an alert in Sentinel if a user logs into more than **one location** within a 7-day time period. Not all alerts will indicate malicious activity, as some may be false positives.  

---

## 🚦 **Creating the Alert Rule (Potential Impossible Travel)**  
**Objective:**  
Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.  

### **Rule Configuration Details:**  
1. **Trigger Conditions:**  
   - A user logs into two or more distinct locations within 7 days.  

2. **KQL Query:**
   
```kql
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
| sort by PotentialImpossibleTravelInstances desc 
```
<img width="1700" height="648" alt="1" src="https://github.com/user-attachments/assets/496fd22d-ee8b-44ba-85ce-75893b8a3f36" />

3. **Analytics Rule Settings:**  
   - **Name:** Potential Impossible Travel Alert  
   - **Description:** Detects logins from multiple geographic regions.  
   - ✅ Enable the Rule.  
   - 🔄 Run Query Every 4 Hours.  
   - 📅 Lookup Data for the Last 24 Hours.  
   - ❌ Stop Running Query After Alert is Generated.  

4. **Entity Mappings:**  
   - **Account ID:** AadUserId → `UserId`  
   - **Display Name:** UserPrincipalName → `Value`  

---

## 🔍 **Detection and Analysis**  

1. **Steps to Validate Incident:**  
   - ✅ Assign the incident to yourself and set the status to **Active**.  
   - 🔄 Use **Investigate** to review entities (may take time).  
   - 📊 Examine output from the analytics rule to identify flagged accounts.  

2. **Account Analysis:**  
   ```kql
   let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
   SigninLogs
   | where TimeGenerated > ago(TimePeriodThreshold)
   | where UserPrincipalName == "b0f7738e0e146afe1560ee169046022c1a9a8c6ca9e77307571a8e3990e121f4@lognpacific.com"
   | project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state),Country = 
   tostring (parse_json(LocationDetails).countryOrRegion)
   | order by TimeGenerated desc 
   ```
   <img width="1700" height="648" alt="2" src="https://github.com/user-attachments/assets/0510de6f-d3f6-428d-b239-2d54353fab61" />

   **Observed Findings:**  
   - **Account 1:** Identifies unusual sign-in behavior where a user account logs in from multiple countries within a short timeframe, indicating impossible travel. 
    
---

## 🛠️ **Containment, Eradication, and Recovery**  

- **Outcome:**  
   The alert was determined to be **True Benign**:  
   - Account activity aligned with expected behavior.  
   - Users logged into locations within reasonable proximity and timeframes.  

- **Next Steps:**  
   - 🔍 Pivot to analyze additional activity for these accounts using:  
     ```kql
     AzureActivity
     | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
     ```  
   - **If suspicious behavior is detected**, disable the account and escalate.  

---

## 🔄 **Post-Incident Activities**  
1. **Policy Updates:**  
   - Implement a **geo-fencing policy** in Azure to restrict logins outside specific regions.  
2. **Documentation:**  
   - Record all findings and lessons learned in the incident management system.  

---

## ✅ **Closure**  
1. **Review Incident:**  
   - Confirm resolution and update notes.  
   - Mark the incident as a **Benign Positive** or **False Positive** (based on findings).  
2. **Finalize Report:**  
   - Submit the report and close the case in Sentinel.  

📌 **Status:** Closed as **Benign Positive**.  

---

**✨ Lessons Learned:**  
- Better geographic restrictions can enhance security.  
- Not all triggers are threats; careful analysis prevents unnecessary escalations.  

📈 **Always stay vigilant!** 🛡️
