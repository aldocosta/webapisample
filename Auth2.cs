using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace WebApiBasicAuth
{
    public class Auth2Attribute : AuthorizeAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (actionContext.Request.Headers.Authorization == null)
            {
                actionContext.Response = actionContext.Request.CreateResponse(System.Net.HttpStatusCode.Unauthorized);
            }
            else
            {
                string authToken = actionContext.Request.Headers.Authorization.Parameter;
                string decodedauthToken = Encoding.UTF8.GetString(Convert.FromBase64String(authToken));
                var usupass = decodedauthToken.Split(':');
                if (usupass[0] == "aldo" && usupass[1] == "costa" && this.Roles.IndexOf("Admin") > -1)
                {
                    Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity(usupass[0]), null);
                }
                else
                {
                    actionContext.Response = actionContext.Request.CreateResponse(System.Net.HttpStatusCode.Unauthorized);
                }
            }
        }
    }
}