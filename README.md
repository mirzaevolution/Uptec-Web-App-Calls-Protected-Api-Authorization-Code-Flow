# Auth Series #4 - Call Microsoft Entra ID/Azure AD Protected Web API via ASP.NET Core MVC using Authorization Code Flow 

![2024 01 18 22H16 04](assets/2024-01-18_22h16_04.gif)

This is 5th tutorial of the **Auth Series**. Before we start, i really encourage you to read 
our previous #1 and #2 tutorials that will have same correlation used in this tutorial.

 - [Auth Series #1 - Microsoft Entra ID/Azure AD Authentication using ASP.NET Core MVC](https://github.com/mirzaevolution/Uptec-Entra-Id-Web-Login)
 - [# Auth Series #2 - Protect ASP.NET Core Api with Microsoft Entra ID/Azure AD and Access It via Postman](https://github.com/mirzaevolution/Uptec-Protected-Web-Api)

In this tutorial, we will create a todo api using ASP.NET Core API 7x and let the Microsoft Entra ID/Azure ID 
as the authorization mechanism to protect our api (OAuth2/JWT). 
Next, we will also create a web app ASP.NET Core MVC 7x that will call our todo api. 
The web app will also get protected by Microsoft Entra ID/Azure AD via OpenID Connect Authorization Code Flow.

Here are the requirements used in this tutorial:

**Requirements:**

- Web Api Framework: ASP.NET Core API 7x
- Web App Framework: ASP.NET Core MVC 7x
- Nuget: Microsoft.Identity.Web and Microsoft.Identity.Web.DownstreamApi

### 1. Expose New API Scope

If you follow along our 2nd tutorial,we have created two new app registrations:

 - uptec-auth-api: This app registration used by our protected WeatherForecast api previously
 - uptec-auth-api-caller: This app registration used client apps to call the protected api

![2024 01 18 10H50 07](assets/2024-01-18_10h50_07.png)

Now, select the **uptec-auth-api** or create new one, and take a note on the client id and tenant id of it.

![2024 01 18 10H50 20](assets/2024-01-18_10h50_20.png)

Go to the **Expose an API** menu, we can see previously we have added a scope named **Access.Read**. 

![2024 01 18 10H52 00](assets/2024-01-18_10h52_00.png)

Now, we need to add new scope named **Access.Write**. These scopes will be used by our API as additional checking mechanism. 
After JWT validated, the api controller can further check whether or not calling api has the required scopes.

![2024 01 18 10H58 54](assets/2024-01-18_10h58_54.png)

Once the new scope created, don't forget to take a note on both scopes as well.


### 2. Register Our Web App and Add The New Scope 'Access.Write'

Switch to App Registration again, and now select the **uptec-auth-api-caller**.
In this page, take a note on the client id and tenant id as well.

![2024 01 18 10H59 38](assets/2024-01-18_10h59_38.png)

Go to the **Certificates & secrets** menu, create new client secret and take a note on it as 
we will use this in the web app to call the api.

![2024 01 18 11H00 23](assets/2024-01-18_11h00_23.png)

To register our web app url, we have to go to **Authentication** page, in the Web Platform, 
add new url `https://localhost:8282/signin-oidc` and `https://localhost:8282/signout-callback-oidc`.
This localhost port 8282 will be used by our application and the reason we register it in here is to 
make sure that we can login/logout and call the api properly.

![2024 01 18 11H28 33](assets/2024-01-18_11h28_33.png)

The last step, we need to request/add new scope from **uptec-auth-api** we have created earlier.
Go to **API permissions**, Click "**Add a permission**" button, in the "**APIs my organization uses/My APIs**", search 
**uptec-auth-api** and select it. 

![2024 01 18 11H29 23](assets/2024-01-18_11h29_23.png)

Select the new scope "**Access.Write**" we created earlier.

![2024 01 18 11H29 47](assets/2024-01-18_11h29_47.png)

### 3. Create ASP.NET Core API - Todo API

Let's create web api for our Todo API. Follow our instructions below.

![2024 01 18 11H31 35](assets/2024-01-18_11h31_35.png)

![2024 01 18 11H57 58](assets/2024-01-18_11h57_58.png)

![2024 01 18 11H58 13](assets/2024-01-18_11h58_13.png)


Go to the **launchSettings.json** and modify the content to be like this:

```
{
  "$schema": "https://json.schemastore.org/launchsettings.json",
  "profiles": {
    "https": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": false,
      "applicationUrl": "https://localhost:8181;",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}

```
![2024 01 18 12H02 04](assets/2024-01-18_12h02_04.png)

Go to the nuget package, please add the following nuget package as well 
`Microsoft.Identity.Web`.

![2024 01 18 12H03 17](assets/2024-01-18_12h03_17.png)

