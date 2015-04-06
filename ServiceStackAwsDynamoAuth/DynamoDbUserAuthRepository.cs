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
    public class DynamoDbUserAuthRepository: IUserAuthRepository
    {
        private readonly AmazonDynamoDBClient client;
        private readonly UserAuthTableConfiguraton configuration;
        private readonly Func<int> idGeneratorFunc;

        public DynamoDbUserAuthRepository(AmazonDynamoDBClient client, UserAuthTableConfiguraton configuration, Func<int> idGeneratorFunc)
        {
            if (client == null)
                throw new ArgumentNullException("client");
            if (configuration == null)
                throw new ArgumentNullException("configuration");
            if (idGeneratorFunc == null)
                throw new ArgumentNullException("idGeneratorFunc");
            
            this.client = client;
            this.configuration = configuration;
            this.idGeneratorFunc = idGeneratorFunc;
        }

        public void Provision(int readCapacity, int writeCapacity)
        {
            var emailToUserMappingTableCreate = new CreateTableRequest() {
                TableName = configuration.EmailToIdMappingTableName,
                ProvisionedThroughput = new ProvisionedThroughput(readCapacity, writeCapacity),
                AttributeDefinitions = new List<AttributeDefinition>() {
                    new AttributeDefinition(configuration.Fields.Email, ScalarAttributeType.S),
                },
                KeySchema = new List<KeySchemaElement>() {
                    new KeySchemaElement(configuration.Fields.Email, KeyType.HASH),
                },
            };
            var usernameToUserMappingTableCreate = new CreateTableRequest() {
                TableName = configuration.UserNameToIdMappingTableName,
                ProvisionedThroughput = new ProvisionedThroughput(readCapacity, writeCapacity),
                AttributeDefinitions = new List<AttributeDefinition>() {
                    new AttributeDefinition(configuration.Fields.UserName, ScalarAttributeType.S),
                },
                KeySchema = new List<KeySchemaElement>() {
                    new KeySchemaElement(configuration.Fields.UserName, KeyType.HASH),
                },
            };
            var userAuthTableCreate = new CreateTableRequest() {
                TableName = configuration.UserAuthTableName,
                ProvisionedThroughput = new ProvisionedThroughput(readCapacity, writeCapacity),
                AttributeDefinitions = new List<AttributeDefinition>() {
                    new AttributeDefinition(configuration.Fields.Id, ScalarAttributeType.N),
                    new AttributeDefinition(configuration.Fields.UserName, ScalarAttributeType.S),
                    new AttributeDefinition(configuration.Fields.Email, ScalarAttributeType.S),
                },
                KeySchema = new List<KeySchemaElement>() {
                    new KeySchemaElement(configuration.Fields.Id, KeyType.HASH),
                },
            };
            userAuthTableCreate.GlobalSecondaryIndexes = new List<GlobalSecondaryIndex>() {
                new GlobalSecondaryIndex() {
                    IndexName = configuration.EmailGlobalIndexName,
                    ProvisionedThroughput = new ProvisionedThroughput(5, 1),
                    KeySchema = new List<KeySchemaElement>() {
                        new KeySchemaElement(configuration.Fields.Email, KeyType.HASH),
                    },
                    Projection = new Projection() { ProjectionType = "ALL" },
                },
                new GlobalSecondaryIndex() {
                    IndexName = configuration.UserNameGlobalIndexName,
                    ProvisionedThroughput = new ProvisionedThroughput(5, 1),
                    KeySchema = new List<KeySchemaElement>() {
                        new KeySchemaElement(configuration.Fields.UserName, KeyType.HASH),
                    },
                    Projection = new Projection() { ProjectionType = "ALL" },
                },
            };
            var userAuthDetailsTableCreate = new CreateTableRequest() {
                TableName = configuration.UserAuthDetailsTableName,
                ProvisionedThroughput = new ProvisionedThroughput(readCapacity, writeCapacity),
                AttributeDefinitions = new List<AttributeDefinition>() {
                    new AttributeDefinition(configuration.Fields.UserAuthId, ScalarAttributeType.N),
                    new AttributeDefinition(configuration.Fields.Provider, ScalarAttributeType.S),
                },
                KeySchema = new List<KeySchemaElement>() {
                    new KeySchemaElement(configuration.Fields.UserAuthId, KeyType.HASH),
                    new KeySchemaElement(configuration.Fields.Provider, KeyType.RANGE),
                },
            };
            try
            {
                var tables = client.DescribeTable(userAuthTableCreate.TableName);    
            }
            catch (ResourceNotFoundException)
            {
                Log.Verbose("Creating tables");
                client.CreateTable(userAuthTableCreate);
                client.CreateTable(userAuthDetailsTableCreate);
                client.CreateTable(usernameToUserMappingTableCreate);
                client.CreateTable(emailToUserMappingTableCreate);
            }
        }

        #region IUserAuthRepository implementation

        public IUserAuth CreateUserAuth(IUserAuth newUser, string password)
        {
            newUser.ThrowIfNull();
            password.ThrowIfNullOrEmpty("password");
            newUser.Id = this.idGeneratorFunc();
            using (var registration = new UserRegistration(newUser, client, configuration))
            {
                registration.Validate();

                var saltedHash = new SaltedHash();
                string salt;
                string hash;
                saltedHash.GetHashAndSaltString(password, out hash, out salt);

                newUser.PasswordHash = hash;
                newUser.Salt = salt;
                var digestHelper = new DigestAuthFunctions();
                newUser.DigestHa1Hash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
                newUser.CreatedDate = DateTime.UtcNow;
                newUser.ModifiedDate = newUser.CreatedDate;

                registration.Register();

                return newUser;
            }
        }

        public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser, string password)
        {
            newUser.ThrowIfNull();
            password.ThrowIfNullOrEmpty("password");
            newUser.Id = existingUser.Id;
            using (var registration = new UserRegistration(newUser, client, configuration))
            {
                registration.Validate();

                var hash = existingUser.PasswordHash;
                var salt = existingUser.Salt;
                if (password != null)
                {
                    var saltedHash = new SaltedHash();
                    saltedHash.GetHashAndSaltString(password, out hash, out salt);
                }
                // If either one changes the digest hash has to be recalculated
                var digestHash = existingUser.DigestHa1Hash;
                if (password != null || existingUser.UserName != newUser.UserName)
                {
                    var digestHelper = new DigestAuthFunctions();
                    digestHash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
                }

                newUser.PasswordHash = hash;
                newUser.Salt = salt;
                newUser.DigestHa1Hash = digestHash;
                newUser.CreatedDate = existingUser.CreatedDate;
                newUser.ModifiedDate = DateTime.UtcNow;

                registration.Update();

                return newUser;
            }
        }

        public IUserAuth GetUserAuth(string userAuthId)
        {
            int id;
            if (userAuthId == null || !int.TryParse(userAuthId, out id))
            {
                return null;
            }
            return GetUserAuth(id);
        }

        private IUserAuth GetUserAuth(int userAuthId)
        {
            using (var context = new DynamoDBContext(client))
            {
                return context.Load<UserAuth>(userAuthId, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthTableName
                });
            }
        }

        #endregion

        #region IAuthRepository implementation

        public void LoadUserAuth(IAuthSession session, IAuthTokens tokens)
        {
            session.ThrowIfNull("session");

            var userAuth = GetUserAuth(session, tokens);
            LoadUserAuth(session, userAuth);
        }

        public void SaveUserAuth(IAuthSession authSession)
        {
            var userAuth = !authSession.UserAuthId.IsNullOrEmpty()
                ? GetUserAuth(authSession.UserAuthId)
                : authSession.ConvertTo<UserAuth>();

            if (userAuth.Id == default(int) && !authSession.UserAuthId.IsNullOrEmpty())
            {
                userAuth.Id = int.Parse(authSession.UserAuthId);
            }

            this.SaveUserAuth(userAuth);
        }

        public List<IUserAuthDetails> GetUserAuthDetails(string userAuthId)
        {
            userAuthId.ThrowIfNullOrEmpty("userAuthId");

            long longId;
            if (userAuthId == null || !long.TryParse(userAuthId, out longId))
            {
                return new List<IUserAuthDetails>();
            }
            using (var context = new DynamoDBContext(client))
            {
                return context.Query<UserAuthDetails>(longId, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthDetailsTableName
                }).Cast<IUserAuthDetails>().ToList();
            }
        }

        public IUserAuthDetails CreateOrMergeAuthSession(IAuthSession authSession, IAuthTokens tokens)
        {
            var authDetails = GetAuthProviderByUserId(tokens.Provider, tokens.UserId);

            var userAuth = GetUserAuth(authSession, tokens);
            if (userAuth == null)
            {
                userAuth = new UserAuth();
                userAuth.Id = this.idGeneratorFunc();
            }

            if (authDetails == null)
            {
                authDetails = new UserAuthDetails();
                authDetails.Id = this.idGeneratorFunc();
                authDetails.UserAuthId = userAuth.Id;
                authDetails.Provider = tokens.Provider;
                authDetails.UserId = tokens.UserId;
            }

            authDetails.PopulateMissing(tokens, overwriteReserved: true);
            userAuth.PopulateMissingExtended(authDetails);

            userAuth.ModifiedDate = DateTime.UtcNow;
            if (authDetails.CreatedDate == default(DateTime))
            {
                authDetails.CreatedDate = userAuth.ModifiedDate;
            }
            authDetails.ModifiedDate = userAuth.ModifiedDate;

            SaveUserAuth(userAuth);
            using (var context = new DynamoDBContext(client))
            {
                var record = new UserAuthDetails();
                record.PopulateWith(authDetails);
                context.Save<UserAuthDetails>(record, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthDetailsTableName
                });
            }
            return authDetails;
        }

        public IUserAuth GetUserAuth(IAuthSession authSession, IAuthTokens tokens)
        {
            if (!authSession.UserAuthId.IsNullOrEmpty())
            {
                var userAuth = GetUserAuth(authSession.UserAuthId);
                if (userAuth != null)
                {
                    return userAuth;
                }
            }
            if (!authSession.UserAuthName.IsNullOrEmpty())
            {
                var userAuth = GetUserAuthByUserName(authSession.UserAuthName);
                if (userAuth != null)
                {
                    return userAuth;
                }
            }

            if (tokens == null || tokens.Provider.IsNullOrEmpty() || tokens.UserId.IsNullOrEmpty())
            {
                return null;
            }

            var oauthProvider = GetAuthProviderByUserId(tokens.Provider, tokens.UserId);
            if (oauthProvider != null)
            {
                return GetUserAuth(oauthProvider.UserAuthId);
            }
            return null;
        }

        public IUserAuth GetUserAuthByUserName(string userNameOrEmail)
        {
            if (userNameOrEmail == null)
                return null;

            var byEmailQuery = new QueryOperationConfig() {
                IndexName = configuration.EmailGlobalIndexName,
                Filter = new QueryFilter(configuration.Fields.Email, QueryOperator.Equal, userNameOrEmail)
            };
            var byUserNameQuery = new QueryOperationConfig() {
                IndexName = configuration.UserNameGlobalIndexName,
                Filter = new QueryFilter(configuration.Fields.UserName, QueryOperator.Equal, userNameOrEmail)
            };
            var isEmail = userNameOrEmail.Contains("@");
            using (var context = new DynamoDBContext(client))
            {
                var result = context.FromQuery<UserAuth>(isEmail ? byEmailQuery : byUserNameQuery);
                return result.SingleOrDefault();
            }
        }

        public void SaveUserAuth(IUserAuth userAuth)
        {
            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default(DateTime))
            {
                userAuth.CreatedDate = userAuth.ModifiedDate;
            }
            using (var registration = new UserRegistration(userAuth, client, configuration))
            {
                registration.Validate();
                registration.Update();
            }
        }

        public bool TryAuthenticate(string userName, string password, out IUserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(userName);
            if (userAuth == null)
            {
                return false;
            }

            var saltedHash = new SaltedHash();
            if (saltedHash.VerifyHashString(password, userAuth.PasswordHash, userAuth.Salt))
            {
                return true;
            }

            userAuth = null;
            return false;
        }

        public bool TryAuthenticate(Dictionary<string, string> digestHeaders, string privateKey, int nonceTimeOut, string sequence, out IUserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(digestHeaders["username"]);
            if (userAuth == null)
            {
                return false;
            }
            
            var digestHelper = new DigestAuthFunctions();
            if (digestHelper.ValidateResponse(digestHeaders, privateKey, nonceTimeOut, userAuth.DigestHa1Hash, sequence))
            {
                return true;
            }
            userAuth = null;
            return false;
        }

        #endregion

        public void DeleteUserAuth(string userAuthId)
        {
            var existingUser = GetUserAuth(userAuthId);
            if (existingUser == null)
                return;
    
            using (var registration = new UserRegistration(existingUser, client, configuration))
            {
                registration.Remove();
            }

            var table = Table.LoadTable(client, this.configuration.UserAuthDetailsTableName);
            var docs = table.Query(existingUser.Id, new QueryFilter());
            var batch = table.CreateBatchWrite();
            var results = docs.GetNextSet();
            while (results.Count > 0)
            {
                results.ForEach(batch.AddItemToDelete);

                results = docs.GetNextSet();
            }
            batch.Execute();
        }

        private void LoadUserAuth(IAuthSession session, IUserAuth userAuth)
        {
            if (userAuth == null)
                return;

            var originalId = session.Id;
            session.PopulateWith(userAuth);
            session.Id = originalId;
            session.UserAuthId = userAuth.Id.ToString(CultureInfo.InvariantCulture);
            session.ProviderOAuthAccess = GetUserAuthDetails(session.UserAuthId).ConvertAll(x => (IAuthTokens)x);
        }

        private IUserAuthDetails GetAuthProviderByUserId(string provider, string userAuthId)
        {
            int id;
            if (userAuthId == null || !int.TryParse(userAuthId, out id))
            {
                return null;
            }
            return GetAuthProviderByUserId(provider, id);
        }

        private IUserAuthDetails GetAuthProviderByUserId(string provider, int userAuthId)
        {
            using (var context = new DynamoDBContext(client))
            {
                return context.Load<UserAuthDetails>(userAuthId, provider, new DynamoDBOperationConfig() {
                    OverrideTableName = this.configuration.UserAuthDetailsTableName
                });
            }
        }
    }
}

