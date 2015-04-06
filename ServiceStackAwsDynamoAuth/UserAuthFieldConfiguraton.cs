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
    public class UserAuthFieldConfiguraton
    {
        public static readonly UserAuthFieldConfiguraton Defaults = new UserAuthFieldConfiguraton() {
            Id = "Id",
            Email = "Email",
            UserName = "UserName",
            Provider = "Provider",
            UserAuthId = "UserAuthId",
        };

        public string Id { get; set; }

        public string Email { get; set; }

        public string UserName { get; set; }

        public string Provider { get; set; }

        public string UserAuthId { get; set; }
    }
}
