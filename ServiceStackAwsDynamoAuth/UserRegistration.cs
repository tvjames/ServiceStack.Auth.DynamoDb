using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using ServiceStack;
using ServiceStack.Auth;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using System.Linq;
using System.Globalization;
using Stateless;
using Serilog;

namespace ServiceStackAwsDynamoAuth
{
    public class UserRegistration : IDisposable
    {
        //http://stackoverflow.com/questions/3588623/c-sharp-regex-for-a-username-with-a-few-restrictions
        public static readonly Regex ValidUserNameRegEx = new Regex(@"^(?=.{3,15}$)([A-Za-z0-9][._-]?)*$", RegexOptions.Compiled);

        private enum States
        {
            Unregistered,
            Validating,
            Registering,
            Registered,
            Updating,
            Removing,
            Removed,
        }

        private enum Triggers
        {
            Restore,
            Validate,
            Validated,
            Register,
            Registered,
            Update,
            Remove,
            Removed,
            Cleanup,
        }

        private readonly IUserAuth userAuth;
        private readonly StateMachine<States, Triggers> fsm;
        private readonly Document mapping;
        private readonly AmazonDynamoDBClient client;
        private readonly UserAuthTableConfiguraton configuration;
        private readonly Table emailMappingTable;
        private readonly Table usernameMappingTable;

        public UserRegistration(IUserAuth userAuth, AmazonDynamoDBClient client, UserAuthTableConfiguraton configuration)
        {
            if (userAuth == null)
                throw new ArgumentNullException("userAuth");
            if (client == null)
                throw new ArgumentNullException("client");
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            this.userAuth = userAuth;
            this.client = client;
            this.configuration = configuration;
            this.fsm = new StateMachine<States, Triggers>(States.Unregistered);

            this.fsm.Configure(States.Unregistered)
                .OnEntryFrom(Triggers.Cleanup, this.Cleanup)
                .Permit(Triggers.Validate, States.Validating)
                .Permit(Triggers.Restore, States.Registered)
                .PermitIf(Triggers.Register, States.Registering, () => this.Validated)
                .PermitReentry(Triggers.Cleanup);

            this.fsm.Configure(States.Validating)
                .OnEntry(this.OnValidate)
                .PermitIf(Triggers.Validated, States.Unregistered, () => !this.Registered)
                .PermitIf(Triggers.Validated, States.Registered, () => this.Registered)
                .Permit(Triggers.Cleanup, States.Unregistered)
                .PermitReentry(Triggers.Validate);

            this.fsm.Configure(States.Registering)
                .OnEntry(this.OnRegistering)
                .PermitIf(Triggers.Registered, States.Registered, () => this.Registered)
                .Permit(Triggers.Cleanup, States.Unregistered);

            this.fsm.Configure(States.Registered)
                .OnEntry(this.OnRegistered)
                .OnExit(this.LeavingRegistered)
                .Permit(Triggers.Validate, States.Validating)
                .PermitIf(Triggers.Update, States.Updating, () => this.Validated)
                .Permit(Triggers.Remove, States.Removing)
                .Permit(Triggers.Cleanup, States.Unregistered);

            this.fsm.Configure(States.Updating)
                .OnEntry(this.OnUpdating)
                .PermitIf(Triggers.Registered, States.Registered, () => this.Registered)
                .Permit(Triggers.Cleanup, States.Unregistered);

            this.fsm.Configure(States.Removing)
                .OnEntry(this.OnRemoving)
                .PermitIf(Triggers.Removed, States.Removed, () => !this.Registered)
                .Permit(Triggers.Cleanup, States.Unregistered);

            this.mapping = new Document();
            mapping[this.configuration.Fields.UserName] = NormaliseIdentifier(userAuth.UserName);
            mapping[this.configuration.Fields.Email] = NormaliseIdentifier(userAuth.Email);
            mapping[this.configuration.Fields.Id] = userAuth.Id;

            this.emailMappingTable = Table.LoadTable(client, configuration.EmailToIdMappingTableName);
            this.usernameMappingTable = Table.LoadTable(client, configuration.UserNameToIdMappingTableName);
        }

        public bool Validated { get; private set; }

        public string ValidationMessage { get; private set; }

        public bool Registered { get; private set; }

        public UserAuth RegisteredUserAuth { get; private set; }

        public bool EmailMapped { get; private set; }

        public bool UserNameMapped { get; private set; }

        public void Restore() {
            this.fsm.Fire(Triggers.Cleanup);
            this.fsm.Fire(Triggers.Restore);
        }

        public void Validate()
        {
            this.fsm.Fire(Triggers.Validate);
            if (!this.Validated)
                throw new ArgumentException(this.ValidationMessage);
            this.fsm.Fire(Triggers.Validated);
        }

        public void Register()
        {
            this.Validate();
            this.fsm.Fire(Triggers.Register);
            this.fsm.Fire(Triggers.Registered);
        }

        public void Update()
        {
            if (this.RegisteredUserAuth == null) {
                this.fsm.Fire(Triggers.Restore);
            }
            this.Validate();
            this.fsm.Fire(Triggers.Update);
            this.fsm.Fire(Triggers.Registered);
        }

        public void Remove()
        {
            if (this.RegisteredUserAuth == null) {
                this.fsm.Fire(Triggers.Restore);
            }
            this.fsm.Fire(Triggers.Remove);
            this.fsm.Fire(Triggers.Removed);
        }

        public void Dispose()
        {
            if (this.fsm.CanFire(Triggers.Cleanup))
                this.fsm.Fire(Triggers.Cleanup);
        }

        private void OnValidate()
        {
            this.ValidateRules();
            this.ValidateUserName();
            this.ValidateEmail();
            this.Validated = true;
        }

        private void ValidateRules()
        {
            if (this.userAuth.UserName.IsNullOrEmpty() && this.userAuth.Email.IsNullOrEmpty())
            {
                throw new ArgumentNullException("UserName or Email is required");
            }

            if (!this.userAuth.UserName.IsNullOrEmpty())
            {
                if (!ValidUserNameRegEx.IsMatch(this.userAuth.UserName))
                {
                    throw new ArgumentException("UserName contains invalid characters", "UserName");
                }
            }
        }

        private void ValidateUserName()
        {
            var userName = NormaliseIdentifier(this.userAuth.UserName);
            if (string.IsNullOrEmpty(userName))
                return;

            // check
            var doc = this.usernameMappingTable.GetItem(userName);
            if (doc != null && doc[this.configuration.Fields.Id].AsInt() != this.userAuth.Id)
            {
                Log.Verbose("{UserId} {UserName} already mapped to {Id}", this.userAuth.Id, this.userAuth.UserName, doc[this.configuration.Fields.Id].AsInt());
                throw new ArgumentException("User {0} already exists".Fmt(this.userAuth.UserName));
            }
            Log.Information("{UserId} {UserName} validated", this.userAuth.Id, this.userAuth.UserName);
        }

        private void ValidateEmail()
        {
            var email = NormaliseIdentifier(this.userAuth.Email);
            if (string.IsNullOrEmpty(email))
                return;

            // check
            var doc = this.emailMappingTable.GetItem(email);
            if (doc != null && doc[this.configuration.Fields.Id].AsInt() != this.userAuth.Id)
            {
                Log.Verbose("{UserId} {Email} already mapped to {Id}", this.userAuth.Id, this.userAuth.Email, doc[this.configuration.Fields.Id].AsInt());
                throw new ArgumentException("Email {0} already exists".Fmt(this.userAuth.Email));
            }
            Log.Information("{UserId} {Email} validated", this.userAuth.Id, this.userAuth.Email);
        }

        private void OnRegistering()
        {
            if (this.RegisteredUserAuth != null)
                return;
            
            this.RegisterUserName();
            this.RegisterEmail();

            Log.Verbose("{UserId} registering {UserName} {Email}", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
            // register user
            using (var context = new DynamoDBContext(client))
            {
                var record = new UserAuth();
                record.PopulateWith(this.userAuth);
                context.Save<UserAuth>(record, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthTableName,
                    ConditionalOperator = ConditionalOperatorValues.And,
                });
                this.RegisteredUserAuth = record;
            }
            this.Registered = true;
            this.UserNameMapped = false;
            this.EmailMapped = false;
            Log.Information("{UserId} {UserName} {Email} registered", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
        }

        private void OnRegistered()
        {
            if (this.RegisteredUserAuth != null)
                return;

            Log.Verbose("{UserId} loading record {UserName} {Email}", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
            // register user
            using (var context = new DynamoDBContext(client))
            {
                this.RegisteredUserAuth = context.Load<UserAuth>(this.userAuth.Id, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthTableName,
                    ConditionalOperator = ConditionalOperatorValues.And,
                });
            }

            if (this.RegisteredUserAuth == null)
                throw new ArgumentException(string.Format("UserAuth {0} not found", this.userAuth.Id));

            this.Registered = true;
            this.UserNameMapped = false;
            this.EmailMapped = false;
            Log.Information("{UserId} {UserName} {Email} registered", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
        }

        private void LeavingRegistered() {
            this.Validated = false;
            this.ValidationMessage = null;

        }

        private string NormaliseIdentifier(string value)
        {
            return (value ?? "").Trim().ToLowerInvariant();
        }

        private void OnUpdating()
        {

            var existingUserName = NormaliseIdentifier(this.RegisteredUserAuth.UserName);
            var existingEmail = NormaliseIdentifier(this.RegisteredUserAuth.Email);
            var currentUserName = NormaliseIdentifier(this.userAuth.UserName);
            var currentEmail = NormaliseIdentifier(this.userAuth.Email);

            // check if username and/or email has changed
            // update and remove if need be
            var usernameWasChanged = false;
            var emailWasChanged = false;
            if (string.Compare(existingUserName, currentUserName, StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                Log.Verbose("{UserId} UserName attribute changed {PreviousUserName} -> {UserName}", this.userAuth.Id, this.RegisteredUserAuth.UserName, this.userAuth.UserName);
                usernameWasChanged = true;
                this.RegisterUserName();
            }
            if (string.Compare(existingEmail, currentEmail, StringComparison.InvariantCultureIgnoreCase) != 0)
            {
                Log.Verbose("{UserId} Email attribute changed {PreviousEmail} -> {Email}", this.userAuth.Id, this.RegisteredUserAuth.Email, this.userAuth.Email);
                emailWasChanged = true;
                this.RegisterEmail();
            }

            Log.Verbose("{UserId} updating {UserName} {Email}", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
            // register user
            using (var context = new DynamoDBContext(client))
            {
                var record = new UserAuth();
                record.PopulateWith(this.userAuth);
                context.Save(record, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthTableName,
                    ConditionalOperator = ConditionalOperatorValues.And,
                });
                this.RegisteredUserAuth = record;
            }
            this.Registered = true;
            this.UserNameMapped = false;
            this.EmailMapped = false;
            Log.Information("{UserId} {UserName} {Email} updated", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);

            if (usernameWasChanged && !string.IsNullOrEmpty(existingUserName))
            {
                Log.Verbose("{UserId} un-mapping previous {UserName}", this.userAuth.Id, existingUserName);
                this.usernameMappingTable.DeleteItem(existingUserName);
                this.UserNameMapped = false;
                Log.Information("{UserId} {UserName} un-mapped", this.userAuth.Id, existingUserName);
            }
            if (emailWasChanged && !string.IsNullOrEmpty(existingEmail))
            {
                Log.Verbose("{UserId} un-mapping previous {Email}", this.userAuth.Id, existingEmail);
                this.emailMappingTable.DeleteItem(existingEmail);
                this.EmailMapped = false;
                Log.Information("{UserId} {Email} un-mapped", this.userAuth.Id, existingEmail);
            }
        }

        private void RegisterUserName()
        {
            var userName = NormaliseIdentifier(this.userAuth.UserName);
            if (string.IsNullOrEmpty(userName))
                return;
            if (this.UserNameMapped)
            {
                Log.Verbose("{UserId} {UserName} already mapped", this.userAuth.Id, this.userAuth.UserName);
                return;
            }

            Log.Verbose("{UserId} mapping {UserName}", this.userAuth.Id, this.userAuth.UserName);
            this.usernameMappingTable.UpdateItem(this.mapping, new UpdateItemOperationConfig() {
                ExpectedState = new ExpectedState() {
                    ConditionalOperator = ConditionalOperatorValues.And,
                    ExpectedValues = new Dictionary<string, ExpectedValue>() {
                        { this.configuration.Fields.UserName, new ExpectedValue(false) },
                    },
                },
                ReturnValues = ReturnValues.None,
            });
            this.UserNameMapped = true;

            Log.Information("{UserId} {UserName} mapped", this.userAuth.Id, this.userAuth.UserName);
        }

        private void RegisterEmail()
        {
            var email = NormaliseIdentifier(this.userAuth.Email);
            if (string.IsNullOrEmpty(email))
                return;
            if (this.EmailMapped)
            {
                Log.Verbose("{UserId} {Email} already mapped", this.userAuth.Id, this.userAuth.Email);
                return;
            }

            Log.Verbose("{UserId} mapping {Email}", this.userAuth.Id, this.userAuth.Email);
            this.emailMappingTable.UpdateItem(this.mapping, new UpdateItemOperationConfig() {
                ExpectedState = new ExpectedState() {
                    ConditionalOperator = ConditionalOperatorValues.And,
                    ExpectedValues = new Dictionary<string, ExpectedValue>() {
                        { this.configuration.Fields.Email, new ExpectedValue(false) },
                    },
                },
                ReturnValues = ReturnValues.None,
            });
            this.EmailMapped = true;

            Log.Information("{UserId} {Email} mapped", this.userAuth.Id, this.userAuth.Email);
        }

        private void OnRemoving()
        {
            var userName = NormaliseIdentifier(this.RegisteredUserAuth.UserName);
            var email = NormaliseIdentifier(this.RegisteredUserAuth.Email);
            this.UserNameMapped = !string.IsNullOrEmpty(userName);
            this.EmailMapped = !string.IsNullOrEmpty(email);
            Log.Verbose("{UserId} removing {UserName} {Email}", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
            // register user
            using (var context = new DynamoDBContext(client))
            {
                context.Delete<UserAuth>(this.userAuth.Id, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthTableName,
                    ConditionalOperator = ConditionalOperatorValues.And,
                });
                this.RegisteredUserAuth = null;
            }
            this.Registered = false;

            if (this.UserNameMapped)
            {
                Log.Verbose("{UserId} un-mapping {UserName}", this.userAuth.Id, this.userAuth.UserName);
                this.usernameMappingTable.DeleteItem(userName);
                this.UserNameMapped = false;
                Log.Information("{UserId} {UserName} un-mapped", this.userAuth.Id, this.userAuth.UserName);
            }
            if (this.EmailMapped)
            {
                Log.Verbose("{UserId} un-mapping previous {Email}", this.userAuth.Id, this.userAuth.Email);
                this.emailMappingTable.DeleteItem(email);
                this.EmailMapped = false;
                Log.Information("{UserId} {Email} un-mapped", this.userAuth.Id, this.userAuth.Email);
            }
            Log.Information("{UserId} {UserName} {Email} removed", this.userAuth.Id, this.userAuth.UserName, this.userAuth.Email);
        }

        private void Cleanup()
        {
            var config = new DeleteItemOperationConfig() {
                ExpectedState = new ExpectedState() {
                    ConditionalOperator = ConditionalOperatorValues.And,
                    ExpectedValues = new Dictionary<string, ExpectedValue>() {
                        { this.configuration.Fields.Email, new ExpectedValue(ScanOperator.Equal, this.userAuth.Email) },
                        { this.configuration.Fields.Id, new ExpectedValue(ScanOperator.Equal, this.userAuth.Id) },
                    },
                },
            };
            if (this.UserNameMapped)
            {
                Log.Verbose("{UserId} un-mapping {UserName}", this.userAuth.Id, this.userAuth.UserName);
                this.usernameMappingTable.DeleteItem(NormaliseIdentifier(this.userAuth.UserName));
                this.UserNameMapped = false;
                Log.Information("{UserId} {UserName} un-mapped", this.userAuth.Id, this.userAuth.UserName);
            }
            if (this.EmailMapped)
            {
                Log.Verbose("{UserId} un-mapping {Email}", this.userAuth.Id, this.userAuth.Email);
                this.emailMappingTable.DeleteItem(NormaliseIdentifier(this.userAuth.Email));
                this.EmailMapped = false;
                Log.Information("{UserId} {Email} un-mapped", this.userAuth.Id, this.userAuth.Email);
            }
        }
    }
}
