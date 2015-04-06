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
    public class UserAuthTableConfiguraton
    {
        public static readonly UserAuthTableConfiguraton Defaults = new UserAuthTableConfiguraton() {
            UserAuthTableName = "UserAuth",
            EmailToIdMappingTableName = "UserAuth-ByEmailMapping",
            UserNameToIdMappingTableName = "UserAuth-ByUsernameMapping",
            UserAuthDetailsTableName = "UserAuthDetails",

            EmailGlobalIndexName = "UserAuthByEmail",
            UserNameGlobalIndexName = "UserAuthByUsername",

            Fields = UserAuthFieldConfiguraton.Defaults,
        };

        public string UserAuthTableName { get; set; }

        public string EmailToIdMappingTableName { get; set; }

        public string UserNameToIdMappingTableName { get; set; }

        public string UserAuthDetailsTableName { get; set; }

        public string EmailGlobalIndexName { get; set; }

        public string UserNameGlobalIndexName { get; set; }

        public UserAuthFieldConfiguraton Fields { get; set; }
    }

}
