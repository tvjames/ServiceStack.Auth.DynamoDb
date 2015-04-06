using System;
using Amazon.DynamoDBv2;
using ServiceStackAwsDynamoAuth;
using Amazon.Runtime;
using Amazon.DynamoDBv2.DataModel;
using ServiceStack.Auth;
using Amazon.DynamoDBv2.Model;
using System.Collections.Generic;
using Amazon.DynamoDBv2.DocumentModel;
using Stateless;
using ServiceStack;
using Serilog;

namespace AuthConsole
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            Serilog.Debugging.SelfLog.Out = Console.Error;
            var log = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .WriteTo.ColoredConsole()
                .CreateLogger();
            Log.Logger = log;
            Log.Information("The global logger has been configured");

            Log.Verbose("Hello World!");

            var credentials = new BasicAWSCredentials("ABC", "dev");
            var config = new AmazonDynamoDBConfig() {
                ServiceURL = "http://127.0.0.1:8091",
                UseHttp = true,
            };
            var client = new AmazonDynamoDBClient(credentials, config);
            Log.Verbose("Client Created!");

            var configuration = UserAuthTableConfiguraton.Defaults;

            var counter = 0;
            var authRepo = new DynamoDbUserAuthRepository(client, configuration, () => ++counter);
            authRepo.Provision(5, 1);
            Log.Verbose("Ready to work");

            // add by email
            var user1 = new UserAuth() {
                Id = 1,
                Email = "user1@example.org",
                UserName = null,
                FirstName = "Tom",
                LastName = "Example",
                FullName = "Tom Example",
                DisplayName = "Tom Example",
            };
            var user1withusername = new UserAuth() {
                Id = 1,
                Email = "user1@example.org",
                UserName = "tomtom",
                FirstName = "Tom",
                LastName = "Example",
                FullName = "Tom Example",
                DisplayName = "Tom Example",
            };
            var user1withemail = new UserAuth() {
                Id = 1,
                Email = "user1a@example.org",
                UserName = "tomtom",
                FirstName = "Tom",
                LastName = "Example",
                FullName = "Tom Example",
                DisplayName = "Tom Example",
            };
            var user2 = new UserAuth() {
                Id = 2,
                Email = "user2@example.org",
                UserName = null,
                FirstName = "Tom",
                LastName = "Example",
                FullName = "Tom Example",
                DisplayName = "Tom Example",
            };

            authRepo.CreateUserAuth(user1, "passworda");
            authRepo.CreateUserAuth(user2, "passwordb");
            authRepo.UpdateUserAuth(user1, user1withemail, "null");
            IUserAuth authenticated;
            var user2Auth = authRepo.TryAuthenticate("user2@example.org", "passwordb", out authenticated);
            var user1Auth = authRepo.TryAuthenticate("user1a@example.org", "null", out authenticated);
            authRepo.DeleteUserAuth("1");
            authRepo.DeleteUserAuth("2");

            try
            {
                using (var newUser1 = new UserRegistration(user1, client, configuration))
                {
                    newUser1.Register();
                }
                using (var newUser1 = new UserRegistration(user1withusername, client, configuration))
                {
                    newUser1.Update();
                }
                using (var newUser1 = new UserRegistration(user1withemail, client, configuration))
                {
                    newUser1.Update();
                }
                using (var newUser1 = new UserRegistration(user1, client, configuration))
                {
                    newUser1.Remove();
                }
                using (var newUser2 = new UserRegistration(user2, client, configuration))
                {
                    newUser2.Register();
                    newUser2.Update();
                    newUser2.Remove();
                }
            }
            catch (ArgumentException exception)
            {
                Log.Error(exception, "ArgumentException when registering user");

                throw;
            }
        }
    }
}
