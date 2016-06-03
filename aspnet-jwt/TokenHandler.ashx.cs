using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Web;
using System.Web.Script.Services;
using System.Web.Services;

namespace aspnet_jwt
{
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [ScriptService]
    public class TokenHandler : IHttpHandler
    {
        // TODO: Convert to SecureString
        // TODO: Load from file and don't store with code
        private const string PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\r\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\r\n  -----END RSA PRIVATE KEY-----";
        private const string AllowedOrigin = "http://localhost:60345";

        public void ProcessRequest(HttpContext context)
        {
            var request = context.Request;
            var referer = request.Headers["Referer"];
            var origin = request.Headers["Origin"];
            if (request.HttpMethod == "POST") // TODO: Restrict access && referer.StartsWith(AllowedOrigin) && origin.StartsWith(AllowedOrigin)
            {
                var now = (int) (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                var jwt = new JWT(PrivateKey)
                {
                    Body =
                    {
                        iss = "https://auth.company.com/v1/token",
                        aud = "https://api.company.com",
                        sub = "notset",
                        exp = now + 86400,
                        iat = now,
                        sid = "{session}",
                        uam = "nemid"
                    },
                };

                var wrapper = new ResponseJSON
                {
                    id_token = jwt.SignAndEncode()
                };

                context.Response.ContentType = "application/json";
                context.Response.Write(JSONUtils.JsonSerialize(wrapper));
                context.Response.Flush();
            }
            else
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                context.Response.Write(JSONUtils.JsonSerialize(new ErrorResponseJSON()
                {
                  type = "authentication_error",
                  message = "Access denied"
                }));
                context.Response.Flush();
            }

            
        }

        public bool IsReusable { get; }
    }

    [DataContract]
    public class ResponseJSON
    {
        [DataMember(EmitDefaultValue = false)]
        public string id_token;
    }

    [DataContract]
    public class ErrorResponseJSON
    {
        [DataMember(EmitDefaultValue = false)]
        public string type;
        [DataMember(EmitDefaultValue = false)]
        public string message;
        [DataMember(EmitDefaultValue = false)]
        public string code;
        [DataMember(EmitDefaultValue = false)]
        public string param;
    }

}