```mermaid
graph LR
  n0["policy:dev-alice-policy"]
  n1(("role:ec2-admin-role"))
  n2(("role:open-admin-role"))
  n3("user:admin-user")
  n4("user:dev-alice")
  n5("user:dev-bob")
  n6("user:dev-carol")
  n7("user:dev-dave")
  n8("user:dev-erin")
  n9("user:dev-frank")
  n10["policy:AdministratorAccess"]
  n11["policy:AmazonS3ReadOnlyAccess"]
  n12["inline:dev-bob/dev-bob-inline"]
  n13["inline:dev-carol/dev-carol-inline"]
  n14["inline:dev-dave/dev-dave-inline"]
  n15["inline:dev-erin/dev-erin-inline"]
  n16["inline:dev-frank/dev-frank-inline"]
  n1 -->|has policy| n10
  n1 -.->|trust allows (account)| n2
  n2 -->|has policy| n10
  n3 -->|has policy| n10
  n3 -.->|trust allows (account)| n2
  n4 -->|has policy| n0
  n4 -.->|trust allows (account)| n2
  n5 -->|has policy| n12
  n5 -.->|trust allows (account)| n2
  n6 -->|has policy| n13
  n6 -.->|trust allows (account)| n2
  n7 -->|has policy| n14
  n7 -.->|trust allows (account)| n2
  n8 -->|has policy| n15
  n8 -.->|trust allows (account)| n2
  n9 -->|has policy| n16
  n9 -.->|trust allows (account)| n2
```
