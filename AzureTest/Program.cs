using Azure.Core;
using Azure.Identity;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class Program
{
    private static readonly string[] context = new [] { "https://database.windows.net//.default" };
    private const string WinAzureCLIError = "'az' is not recognized";
    private static readonly Regex AzNotFoundPattern = new Regex("az:(.*)not found");

    public static async Task<AccessToken> RequestCliAccessTokenAsync_Fixed(bool async, string[] scopes, CancellationToken cancellationToken)
    {
        var resource = ScopeUtilities.ScopesToResource(scopes);
        ScopeUtilities.ValidateScope(resource);

        GetFileNameAndArgumentsForToken(resource, out string fileName, out string argument);
        var processStartInfo = GetAzureCliProcessStartInfo(fileName, argument);

        string output, error;
        try
        {
            (output, error) = await RunAndGrabOutput(processStartInfo);
            if (error.Contains("ERROR: Please run 'az login' to setup account."))
            {
                // what does `az account list` show?
                string commandAccountList = $"\"C:\\Program Files (x86)\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az\" account list";
                GetFileNameAndArguments(out var fileNameAccountList, out var argumentAccountList, commandAccountList);
                var processStartInfoAccountList = GetAzureCliProcessStartInfo(fileNameAccountList, argumentAccountList);

                string outputAccountList, errorAccountList;
                (outputAccountList, errorAccountList) = await RunAndGrabOutput(processStartInfoAccountList);
                if (!string.IsNullOrEmpty(errorAccountList))
                {
                    throw new InvalidOperationException(errorAccountList);
                }
                else
                {
                    throw new InvalidOperationException(error);
                }
            }
            return DeserializeOutput(output);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuthenticationFailedException("AzureCliTimeoutError");
        }
        catch (InvalidOperationException exception)
        {
            bool isWinError = exception.Message.StartsWith(WinAzureCLIError, StringComparison.CurrentCultureIgnoreCase);
            bool isOtherOsError = AzNotFoundPattern.IsMatch(exception.Message);

            if (isWinError || isOtherOsError)
            {
                throw new CredentialUnavailableException("AzureCLINotInstalled");
            }

            bool isLoginError = exception.Message.IndexOf("az login", StringComparison.OrdinalIgnoreCase) != -1;

            if (isLoginError)
            {
                throw new CredentialUnavailableException("AzNotLogIn");
            }

            throw new AuthenticationFailedException($"AzureCliFailedError {exception.Message}");
        }
    }

    private static async Task<(string output, string error)> RunAndGrabOutput(ProcessStartInfo processStartInfo)
    {
        var process = Process.Start(processStartInfo);
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (output, error);
    }

    private static AccessToken DeserializeOutput(string output)
    {
        using JsonDocument document = JsonDocument.Parse(output);

        JsonElement root = document.RootElement;
        string accessToken = root.GetProperty("accessToken").GetString();
        DateTimeOffset expiresOn = root.TryGetProperty("expiresIn", out JsonElement expiresIn)
            ? DateTimeOffset.UtcNow + TimeSpan.FromSeconds(expiresIn.GetInt64())
            : DateTimeOffset.ParseExact(root.GetProperty("expiresOn").GetString(), "yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.CurrentCulture.DateTimeFormat);

        return new AccessToken(accessToken, expiresOn);
    }

    private static void GetFileNameAndArgumentsForToken(string resource, out string fileName, out string argument)
    {
        string command = $"\"C:\\Program Files (x86)\\Microsoft SDKs\\Azure\\CLI2\\wbin\\az\" account get-access-token --output json --resource {resource}";
        GetFileNameAndArguments(out fileName, out argument, command);
    }

    private static void GetFileNameAndArguments(out string fileName, out string argument, string command)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            fileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            argument = $"/c \"{command}\"";
        }
        else
        {
            fileName = "/bin/sh";
            argument = $"-c \"{command}\"";
        }
    }

    private static ProcessStartInfo GetAzureCliProcessStartInfo(string fileName, string argument) =>
        new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = argument,
            UseShellExecute = false,
            ErrorDialog = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            LoadUserProfile = true,
            UserName = Environment.UserName,
            PasswordInClearText = File.ReadAllText($"C:\\Users\\{Environment.UserName}\\pw.txt"),
        };


    internal static class ScopeUtilities
    {
        private const string DefaultSuffix = "/.default";
        private const string ScopePattern = "^[0-9a-zA-Z-.:/]+$";

        private const string InvalidScopeMessage = "The specified scope is not in expected format. Only alphanumeric chars only";
        private static readonly Regex scopeRegex = new Regex(ScopePattern);

        public static string ScopesToResource(string[] scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            if (scopes.Length != 1)
            {
                throw new ArgumentException("To convert to a resource string the specified array must be exactly length 1");
            }

            if (!scopes[0].EndsWith(DefaultSuffix, StringComparison.Ordinal))
            {
                return scopes[0];
            }

            return scopes[0].Remove(scopes[0].LastIndexOf(DefaultSuffix, StringComparison.Ordinal));
        }

        public static string[] ResourceToScopes(string resource)
        {
            return new string[] { resource + "/.default" };
        }

        public static void ValidateScope(string scope)
        {
            bool isScopeMatch = scopeRegex.IsMatch(scope);

            if (!isScopeMatch)
            {
                throw new ArgumentException(InvalidScopeMessage, nameof(scope));
            }
        }
    }

    private const string DefaultSuffix = "/.default";
    private const string ScopePattern = "^[0-9a-zA-Z-.:/]+$";

    private const string InvalidScopeMessage = "The specified scope is not in expected format. Only alphanumeric cha";
    private static readonly Regex scopeRegex = new Regex(ScopePattern);

    public static string ScopesToResource(string[] scopes)
    {
        if (scopes == null)
        {
            throw new ArgumentNullException(nameof(scopes));
        }

        if (scopes.Length != 1)
        {
            throw new ArgumentException("To convert to a resource string the specified array must be exactly length 1");
        }

        if (!scopes[0].EndsWith(DefaultSuffix, StringComparison.Ordinal))
        {
            return scopes[0];
        }

        return scopes[0].Remove(scopes[0].LastIndexOf(DefaultSuffix, StringComparison.Ordinal));
    }

    public static string[] ResourceToScopes(string resource)
    {
        return new string[] { resource + "/.default" };
    }

    public static void ValidateScope(string scope)
    {
        bool isScopeMatch = scopeRegex.IsMatch(scope);

        if (!isScopeMatch)
        {
            throw new ArgumentException(InvalidScopeMessage, nameof(scope));
        }
    }

    public static async Task<AccessToken> RequestCliAccessTokenAsync_Original()
    {
        return await new AzureCliCredentialOriginal().GetTokenAsync(new TokenRequestContext(context));
    }

    public static async Task Main(string[] args)
    {
        // This works
        await Program.RequestCliAccessTokenAsync_Fixed(true, context, CancellationToken.None);

        // This does not work
        await Program.RequestCliAccessTokenAsync_Original();

        // Neither does this
        await new Azure.Identity.AzureCliCredential().GetTokenAsync(new TokenRequestContext(context));
    }
}



public class AzureCliCredentialOriginal : TokenCredential
{
    private const string AzureCLINotInstalled = "Azure CLI not installed";
    private const string AzNotLogIn = "Please run 'az login' to set up account";
    private const string WinAzureCLIError = "'az' is not recognized";
    private const string AzureCliTimeoutError = "Azure CLI authentication timed out.";
    private const string AzureCliFailedError = "Azure CLI authentication failed due to an unknown error.";
    private const int CliProcessTimeoutMs = 10000;

    // The default install paths are used to find Azure CLI if no path is specified. This is to prevent executing ou"
    private static readonly string DefaultPathWindows = @"C:\Program Files (x86)\Microsoft SDKs\Azure CLI";
    private static readonly string DefaultWorkingDirWindows = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private const string DefaultPathNonWindows = "/usr/bin:/usr/local/bin";
    private const string DefaultWorkingDirNonWindows = "/bin/";
    private static readonly string DefaultPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? DefaultPathWindows : DefaultPathNonWindows;
    private static readonly string DefaultWorkingDir = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? DefaultWorkingDir : DefaultWorkingDirNonWindows;

    private static readonly Regex AzNotFoundPattern = new Regex("az:(.*)not found");

    private readonly string _path;


    /// <summary>
    /// Obtains a access token from Azure CLI credential, using this access token to authenticate. This method calle
    /// </summary>
    /// <param name="requestContext"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken = default) => throw new NotImplementedException();

    /// <summary>
    /// Obtains a access token from Azure CLI service, using the access token to authenticate. This method id called
    /// </summary>
    /// <param name="requestContext"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
    {
        return await GetTokenImplAsync(true, requestContext, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<AccessToken> GetTokenImplAsync(bool async, TokenRequestContext requestContext, CancellationToken cancellationToken = default)
    {
        try
        {
            AccessToken token = await RequestCliAccessTokenAsync(async, requestContext.Scopes, cancellationToken).ConfigureAwait(!async);
            return token;
        }
        catch (Exception e)
        {
            throw;
            // throw scope.FailWrapAndThrow(e);
        }
    }

    private async ValueTask<AccessToken> RequestCliAccessTokenAsync(bool async, string[] scopes, CancellationToken cancellationToken)
    {
        string resource = Program.ScopesToResource(scopes);

        Program.ValidateScope(resource);

        GetFileNameAndArguments(resource, out string fileName, out string argument);
        ProcessStartInfo processStartInfo = GetAzureCliProcessStartInfo(fileName, argument);
        // VVV Not relevant, can use regular ProcessInfo
        //var processRunner = new ProcessRunner(_processService.Create(processStartInfo), TimeSpan.FromMilliseconds(CliProcessTimeoutMs));

        string output, error;
        try
        {
            //output = async ? await processRunner.RunAsync().ConfigureAwait(false) : processRunner.Run();
            var process = Process.Start(processStartInfo);
            if (async)
            {
                output = await process.StandardOutput.ReadToEndAsync();
                error = await process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();
            }
            else
            {
                output = process.StandardOutput.ReadToEnd();
                error = process.StandardError.ReadToEnd();
                process.WaitForExit();
            }

            if (!string.IsNullOrWhiteSpace(error))
            {
                throw new InvalidOperationException(error);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new AuthenticationFailedException(AzureCliTimeoutError);
        }
        catch (InvalidOperationException exception)
        {
            bool isWinError = exception.Message.StartsWith(WinAzureCLIError, StringComparison.CurrentCultureIgnoreCase);

            bool isOtherOsError = AzNotFoundPattern.IsMatch(exception.Message);

            if (isWinError || isOtherOsError)
            {
                throw new CredentialUnavailableException(AzureCLINotInstalled);
            }

            bool isLoginError = exception.Message.IndexOf("az login", StringComparison.OrdinalIgnoreCase) != -1;// || exception.Message.IndexOf("", StringComparison.OrdinalIgnoreCase) != -1;

            if (isLoginError)
            {
                throw new CredentialUnavailableException(AzNotLogIn);
            }

            throw new AuthenticationFailedException($"{AzureCliFailedError} {exception.Message}");
        }

        return DeserializeOutput(output);
    }

    private ProcessStartInfo GetAzureCliProcessStartInfo(string fileName, string argument) =>
        new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = argument,
            UseShellExecute = false,
            ErrorDialog = false,
            CreateNoWindow = true,
            WorkingDirectory = DefaultWorkingDir,
            Environment = { { "PATH", _path } },
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };

    private static void GetFileNameAndArguments(string resource, out string fileName, out string argument)
    {
        string command = $"az account get-access-token --output json --resource {resource}";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            fileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            argument = $"/c \"{command}\"";
        }
        else
        {
            fileName = "/bin/sh";
            argument = $"-c \"{command}\"";
        }
    }

    private static AccessToken DeserializeOutput(string output)
    {
        using JsonDocument document = JsonDocument.Parse(output);

        JsonElement root = document.RootElement;
        string accessToken = root.GetProperty("accessToken").GetString();
        DateTimeOffset expiresOn = root.TryGetProperty("expiresIn", out JsonElement expiresIn)
            ? DateTimeOffset.UtcNow + TimeSpan.FromSeconds(expiresIn.GetInt64())
            : DateTimeOffset.ParseExact(root.GetProperty("expiresOn").GetString(), "yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.CurrentCulture.DateTimeFormat);

        return new AccessToken(accessToken, expiresOn);
    }
}