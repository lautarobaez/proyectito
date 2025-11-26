using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.IO;

class Program
{
    static async Task Main()
    {
        Console.WriteLine("===== MONITOREO BÁSICO DE RED LAN =====");
        Console.WriteLine("Escaneando red local...\n");

        // CAMBIAR SEGÚN TU RED — por ejemplo 192.168.0 o 10.0.0
        string baseIp = "192.168.1";

        // Dónde guardar el archivo
        string filePath = "hosts.csv";

        // Cabecera del CSV (si no existe)
        if (!File.Exists(filePath))
        {
            File.WriteAllText(filePath, "Fecha,IP,Hostname\n");
        }

        var hostsActivos = await EscanearRed(baseIp);

        Console.WriteLine("\n=== RESULTADOS ===");

        foreach (var ip in hostsActivos.OrderBy(x => x))
        {
            string hostname = ObtenerHostname(ip);
            Console.WriteLine($"{ip} - {hostname}");

            // Guardar en CSV
            File.AppendAllText(filePath, $"{DateTime.Now},{ip},{hostname}\n");
        }

        Console.WriteLine($"\nEscaneo finalizado. Datos guardados en: {filePath}");
        Console.WriteLine("Presiona Enter para salir...");
        Console.ReadLine();
    }

    // Función que recorre todas las IP del rango
    static async Task<ConcurrentBag<string>> EscanearRed(string baseIp)
    {
        var vivos = new ConcurrentBag<string>();

        var tareas = Enumerable.Range(1, 254).Select(i => Task.Run(async () =>
        {
            string ip = $"{baseIp}.{i}";
            using Ping p = new Ping();

            try
            {
                var respuesta = await p.SendPingAsync(ip, 300);
                if (respuesta.Status == IPStatus.Success)
                {
                    vivos.Add(ip);
                }
            }
            catch { }
        })).ToArray();

        await Task.WhenAll(tareas);

        return vivos;
    }

    // Intenta obtener el nombre del host
    static string ObtenerHostname(string ip)
    {
        try
        {
            var entry = Dns.GetHostEntry(ip);
            return entry.HostName;
        }
        catch
        {
            return "(hostname no disponible)";
        }
    }
}
