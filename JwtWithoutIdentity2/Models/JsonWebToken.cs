﻿namespace JwtWithoutIdentity2.Models
{
    internal class JsonWebToken
    {
        public JsonWebToken()
        {
        }

        public string access_token { get; set; }
        public int expires_in { get; set; }
        public string token_type { get; set; }
    }
}