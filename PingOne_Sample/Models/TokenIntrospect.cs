using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace PingOne_Sample.Models
{
    public class TokenIntrospect
    {
        public bool active { get; set; }
        public string scope { get; set; }
        public string client_id { get; set; }

        [JsonProperty("token_type", NullValueHandling = NullValueHandling.Ignore)]
        public string TokenType { get; set; }
        public int exp { get; set; }
        public int iat { get; set; }
        public string sub { get; set; }
        public string[] aud { get; set; }
        public string iss { get; set; }
        public string sid { get; set; }
    }
}