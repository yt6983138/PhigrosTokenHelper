using LeanCloud;
using LeanCloud.Storage;
using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using TapTap.Common;
using TapTap.Login;
using TapTap.Login.Internal;
using TMPro;
using UnityEngine;
using UnityEngine.UI;

public class Startup : MonoBehaviour
{
	public const string ClientId = "kviehleldgxsagpozb";

	private Button _startButton;
	private GameObject _tokenButton;
	private TMP_Text _error;

	private void Awake()
	{
		this._startButton = GameObject.Find("LoginStart").GetComponent<Button>();
		this._tokenButton = GameObject.Find("Token");
		Vector3 pos = this._tokenButton.transform.localPosition;
		pos.x += 100000;
		this._tokenButton.transform.localPosition = pos;
		this._error = GameObject.Find("ErrorText").GetComponent<TMP_Text>();
	}

	// Start is called before the first frame update
	private async void Start()
	{
		//TapConfig config = new TapConfig.Builder()
		//	.ClientID("kviehleldgxsagpozb")
		//	.ClientToken("tG9CTm0LDD736k9HMM9lBZrbeBGRmUkjSfNLDNib")
		//	.ServerURL("https://kviehlel.cloud.ap-sg.tapapis.com")
		//	.RegionType(RegionType.IO)
		//	.ConfigBuilder();
		//TapBootstrap.Init(config);

		//TDSUser user = await TDSUser.LoginWithTapTap(new string[] { "public_profile" });
		//Debug.Log($"Login successful，current token：{user.SessionToken}");

		//TapLogin.Init("kviehleldgxsagpozb", false, false);
		//await TapLogin.Login();

		TapLoginImpl.GetInstance().Init(ClientId, false, false);
		WebLoginRequestManager.Instance.CreateNewLoginRequest(new string[] { "public_profile" });
		WebLoginRequest request = WebLoginRequestManager.Instance.GetCurrentRequest();

		string redirectUri = request.GetRedirectUri();
		string loginUrl = request.GetWebLoginUrl();
		Debug.Log($"Login url: {loginUrl}");
		Debug.Log($"Redirect uri: {redirectUri}");

		HttpListener listener = new();
		listener.Prefixes.Add(request.GetRedirectHost());
		listener.Start();

		this._startButton.onClick.AddListener(() =>
		{
			Application.OpenURL(loginUrl);
		});

		HttpListenerContext context = await listener.GetContextAsync();
		Debug.Log($"Listener got: {context.Request.RawUrl}");

		string code = context.Request.QueryString.Get("code");
		Debug.Log($"Code: {code}");

		context.Response.StatusCode = 200;
		context.Response.ContentType = "text/plain";
		context.Response.ContentLength64 = 0;
		context.Response.OutputStream.Close();

		Dictionary<string, string> @params = new()
		{
			{ "client_id", ClientId },
			{ "grant_type", "authorization_code" },
			{ "secret_type", "hmac-sha-1" },
			{ "code", code },
			{ "redirect_uri", redirectUri },
			{ "code_verifier", WebLoginRequestManager.Instance.GetCodeVerifier() }
		};
		listener.Stop();

		Net net = this.gameObject.AddComponent<Net>();
		net.PostAsync("https://accounts.tapapis.com/oauth2/v1/token", null!, @params, result =>
		{
			Debug.Log($"Result: {result}");

			Dictionary<string, object> resultDict = (Dictionary<string, object>)Json.Deserialize(result);
			if (!(resultDict.TryGetValue("success", out object success) && (bool)success)) return;

			Dictionary<string, object> data = (Dictionary<string, object>)resultDict["data"];
			AccessToken token = new()
			{
				kid = (string)data["kid"],
				macKey = (string)data["mac_key"],
				accessToken = (string)data["access_token"],
				tokenType = (string)data["token_type"],
				macAlgorithm = (string)data["mac_algorithm"]
			};

			this.GetProfileAsync(token, net, async profileResult =>
			{
				Debug.Log($"Profile result: {profileResult}");

				Dictionary<string, object> profileDict = (Dictionary<string, object>)Json.Deserialize(profileResult);
				if (!(profileDict.TryGetValue("success", out object success2) && (bool)success2)) return;

				Dictionary<string, object> profile = (Dictionary<string, object>)profileDict["data"];
				LCApplication.Initialize(ClientId, "tG9CTm0LDD736k9HMM9lBZrbeBGRmUkjSfNLDNib", "https://kviehlel.cloud.ap-sg.tapapis.com");

				Dictionary<string, object> authData = new()
				{
					{"kid", token.kid},
					{"access_token", token.accessToken},
					{"token_type", token.tokenType},
					{"mac_key", token.macKey},
					{"mac_algorithm", token.macAlgorithm},

					{"openid", profile["openid"] },
					{"name", profile["name"] },
					{"avatar", profile["avatar"] },
					{"unionid", profile["unionid"] }
				};

				LCUser user = await LCUser.LoginWithAuthData(authData, "taptap");
				Debug.Log($"Login successful, current user: {user.Username}, Token: {user.SessionToken}");

				Vector3 pos = this._tokenButton.transform.localPosition;
				pos.x = 0;
				this._tokenButton.transform.localPosition = pos;

				this._tokenButton.GetComponentInChildren<TMP_Text>().text = $"Token: {user.SessionToken} (Click to copy)";
				this._tokenButton.GetComponent<Button>().onClick.AddListener(() =>
				{
					GUIUtility.systemCopyBuffer = user.SessionToken;
					Debug.Log("Token copied to clipboard.");
				});
			});

		}, (code, error) =>
		{
			this._error.text = $"Error {code}: {error}";
		});
	}

	public void GetProfileAsync(AccessToken token, Net net, Action<string> onComplete)
	{
		string fetchUrl = $"https://open.tapapis.com/account/profile/v1?client_id={ClientId}";
		Uri uri = new(fetchUrl);
		int timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
		string authorization = GetAuthorizationHeader(token.kid, token.macKey, token.macAlgorithm, "GET", uri.PathAndQuery, uri.Host, "443", timeStamp);
		net.GetAsync(fetchUrl, authorization, null, onComplete, (code, error) =>
		{
			this._error.text = $"Error {code}: {error}";
		});
	}

	// Token: 0x060000AE RID: 174 RVA: 0x00003A80 File Offset: 0x00001C80
	private static string GetAuthorizationHeader(string kid, string macKey, string macAlgorithm, string method, string uri, string host, string port, int timestamp)
	{
		string text = new System.Random().Next().ToString();
		string text2 = string.Format("{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n\n", new object[] { timestamp, text, method, uri, host, port });
		HashAlgorithm hashAlgorithm;
		if (!(macAlgorithm == "hmac-sha-256"))
		{
			if (!(macAlgorithm == "hmac-sha-1"))
			{
				throw new InvalidOperationException("Unsupported MAC algorithm");
			}
			hashAlgorithm = new HMACSHA1(Encoding.ASCII.GetBytes(macKey));
		}
		else
		{
			hashAlgorithm = new HMACSHA256(Encoding.ASCII.GetBytes(macKey));
		}
		string text3 = Convert.ToBase64String(hashAlgorithm.ComputeHash(Encoding.ASCII.GetBytes(text2)));
		StringBuilder stringBuilder = new();
		stringBuilder.AppendFormat("MAC id=\"{0}\",ts=\"{1}\",nonce=\"{2}\",mac=\"{3}\"", new object[] { kid, timestamp, text, text3 });
		return stringBuilder.ToString();
	}
}
