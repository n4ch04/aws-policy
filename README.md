## aws-policies
AWS have an amazing SDK for Go with all API functions output typed, and works like clockwork ... until IAM policy documents appear.  
AWS describes the policy document in SDK (GetPolicyVersion function ), textually, _The policy document returned in this structure is URL-encoded compliant with RFC 3986 (https://tools.ietf.org/html/rfc3986)_  
In practice, its raw data, and parsing it's difficult due to its structure depends on the policy, and not all fields always appear.  
To achieve this I have used golang generics and it seems to work pretty well. 
