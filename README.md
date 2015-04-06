# ServiceStack.Auth.DynamoDb
DynamoDb UserAuth Repo

🐉 Here Be Dragons: This is a proof of concept and definitely not for use in production. It's only been run against DynamoDB Local. 

## Running

* Download [DynamoDB Local](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tools.DynamoDBLocal.html)
* Start it up

```
java -Djava.library.path=./DynamoDBLocal_lib -jar DymoDBLocal.jar  --port 8091
```
* Modify `Program.cs` to your liking.

## TODO

* Tests
* Package for nuget
* Cleanup & revise namespaces, assembly names etc
* Rethink FSM states/triggers
* Test against DynamoDB endpoints
