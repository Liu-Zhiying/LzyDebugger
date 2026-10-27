using Microsoft.AspNetCore.Http.HttpResults;
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json.Serialization;

namespace SymbolCacher
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(args);

            string logPath = "logs.log";

            builder.Logging.AddFile(o => o.Path = logPath);

            builder.Services.AddSingleton<GetPdb>();

            builder.Services.AddHttpClient();

            var app = builder.Build();

            app.Map("/get_pdb/{pdbFile1}/{signature}/{pdbFile2}", app.Services.GetService<GetPdb>()!.GetPdbRequest);

            app.Run();
        }
    }
}
