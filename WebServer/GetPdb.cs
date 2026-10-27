using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using System.Net;
using System.Text;

namespace SymbolCacher
{
    public class GetPdb
    {
        private ILogger<GetPdb> logger;
        private HttpClient client;

        public GetPdb(ILogger<GetPdb> _logger, HttpClient _client)
        {
            logger = _logger; 
            client = _client;
        }

        private string GetPdbFile(string pdbFile, string signature)
        {
            char sep = Environment.OSVersion.Platform == PlatformID.Win32NT ? '\\' : '/';
            string pdbPath = "pdb_cache";
            string pathSuffix = $"{sep}{pdbFile}" + $"{sep}{signature}";
            string currentDIr = Directory.GetCurrentDirectory();
            if (currentDIr.EndsWith(sep)) currentDIr.Remove(currentDIr.Length - 1);

            if (!Directory.Exists(pdbPath + pathSuffix)) return string.Empty;
            if (!Directory.Exists(pdbPath + pathSuffix)) return string.Empty;
            if (!File.Exists(pdbPath + pathSuffix + $"{sep}{pdbFile}")) return string.Empty;
            else return currentDIr + $"{sep}{pdbPath}" + pathSuffix + $"{sep}{pdbFile}";
        }

        private async void CachePdbFile(string pdbFile, string signature, Stream fileStream)
        {
            char sep = Environment.OSVersion.Platform == PlatformID.Win32NT ? '\\' : '/';
            string pdbPath = "pdb_cache";
            string pathSuffix = $"{sep}{pdbFile}" + $"{sep}{signature}";
            string currentDIr = Directory.GetCurrentDirectory();

            if (!Directory.Exists(pdbPath + $"{sep}{pdbFile}"))
                Directory.CreateDirectory(pdbPath + $"{sep}{pdbFile}");

            if (!Directory.Exists(pdbPath + pathSuffix))
                Directory.CreateDirectory(pdbPath + pathSuffix);

            if (File.Exists(pdbPath + pathSuffix + $"{sep}{pdbFile}"))
            {
                fileStream.Close();
                return;
            }

            FileStream cacheFileStream = File.Open(pdbPath + pathSuffix + $"{sep}{pdbFile}", FileMode.Create);

            await Task.Run(() => {
                try
                {
                    fileStream.CopyTo(cacheFileStream);
                    cacheFileStream.Close();
                    fileStream.Close();
                }
                catch (Exception)
                {

                }
            });
        }

        public async Task<IResult> GetPdbRequest(string pdbFile1, string signature, string pdbFile2)
        {
            if (pdbFile1 != pdbFile2)
            {
                logger.LogError("pdbFile1 != pdbFile2");
                return Results.Text("<h1>Url request parameter error!<h1>", "text/html", Encoding.UTF8, 403);
            }

            string pdbFilePath = GetPdbFile(pdbFile1, signature);
            if (pdbFilePath.Length != 0)
            {
                try
                {
                    logger.LogInformation($"Try to return result from {pdbFilePath}.");
                    return Results.File(File.ReadAllBytes(pdbFilePath), "application/octet-stream", pdbFile1);
                }
                catch (Exception)
                {
                    logger.LogInformation("Return result from cache file failed.");
                }
            }

            do
            {
                try
                {
                    const string url_base = "https://msdl.microsoft.com/download/symbols/";
                    string url = url_base + "/" + pdbFile1 + "/" + signature + "/" + pdbFile1;

                    logger.LogInformation($"Try to return result from {url}.");

                    HttpResponseMessage response1 = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
                    HttpResponseMessage response2 = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);

                    if (response1.Content.Headers.ContentLength == 0)
                        break;

                    Stream responseBody1 = await response1.Content.ReadAsStreamAsync();
                    Stream responseBody2 = await response1.Content.ReadAsStreamAsync();

                    CachePdbFile(pdbFile1, signature, responseBody2);

                    return Results.Stream(responseBody1, "application/octet-stream", pdbFile1);
                }
                catch (Exception)
                {
                    break;
                }

            }
            while (false);

            return Results.Text("<h1>There is no file in Microsoft Public Symbol Server.</h1>",
                                        "text/html",
                                        Encoding.UTF8,
                                        404);
        }
    }
}
