## AWS-Policy
[![Go Reference](https://pkg.go.dev/badge/github.com/n4ch04/aws-policy.svg)](https://pkg.go.dev/github.com/n4ch04/aws-policy)  

AWS have an amazing SDK for Go with all API functions output typed, and works like clockwork ... until IAM policy documents appear.  

AWS describes the policy document in SDK (GetPolicyVersion function ), textually, _The policy document returned in this structure is URL-encoded compliant with RFC 3986 _(https://tools.ietf.org/html/rfc3986)_

In practice, it's raw data, and parsing it's difficult due to it's structure depends on the policy, and not all fields always appear.  
To achieve this I have used golang generics and it seems to work pretty well. 
