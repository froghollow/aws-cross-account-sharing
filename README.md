# AWS Cross-Account Resource Sharing

[AWS Cross-Account resource access enables](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html#access_policies-cross-account-using-resource-based-policies) sharing of resources among AWS Accounts.   Cross Account Resource Sharing avoids duplication of data and eliminates redundant configurations.  Why copy data from one account to another when it can be shared in place?  Why build and configure multiple toolsets when one tool can share common data?

This project includes an [AWS Cross-Account Resource Sharing Notebook](cross_acct.ipynb) that provides examples how to configure IAM Roles and Policies between a **Shared Account** which contains resources to be made accessible to a **Trusted Account**.  It shows how to use [iam_cross_account.py](python/iam_cross_account.py) common code module to support 3 scenarios.  
- Query Existing Existing Role & Policy Configurations
- Generate Cross Account Configurations from Templates
- Create/Update IAM Roles and Policies from JSON Config Doc

Cross-account configurations are not difficult, but they are detailed.  And several approaches yield similar results.  The goal this workbook is to promote standardization of Cross-account configurations.

### Additional Considerations

This project focuses on sharing Amazon S3.   Many other [AWS Services can participate in cross-account sharing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html), as long as they support 'resource-based policies', some of which include:
- EFS
- EventBridge
- Glue
- KMS
- Lambda
- Secrets Manager
- SNS
- SES
- S3
- Systems Manager

Please note that [cross-account sharing must be between accounts *within the same partition*](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html). For example, assume that you have an account in US East 2 (Ohio) in the standard commercial 'aws' partition. You also have an account in AWS GovCloud West 'aws-us-gov' partition. You can't use an Amazon S3 resource-based policy in your GovCloud account to allow access to buckets in your commercial account.  

### References
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html
