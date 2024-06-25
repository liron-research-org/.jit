// introducing different types of vulnerabilities to be caught by different rules

using System;
using System.DirectoryServices;
using System.IO;
using Newtonsoft.Json;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Web.UI;
using System.Runtime.Serialization.Formatters.Soap;
using System.Runtime.Serialization;
using fastJSON;
using MBrace.FsPickler.Json;
using System.Web.Script.Serialization;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;

namespace LDAPInjectionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Enter LDAP filter: ");
            string userInput = Console.ReadLine();

            DirectorySearcher searcher = new DirectorySearcher();
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(displayName=" + userInput + "))";

            SearchResultCollection results = searcher.FindAll();
            Console.WriteLine("Results found: " + results.Count);
        }

        static void VulnerableMethod(string input)
        {
            DirectorySearcher searcher = new DirectorySearcher();
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(displayName=" + input + "))";
        }
    }
}

namespace DeprecatedCipherAlgorithmExample
{
    class Program
    {
        static void Main(string[] args)
        {
            // Usage of deprecated cipher algorithm (DES)
            DES des = DES.Create();
            Console.WriteLine("DES algorithm created.");
        }
    }
}



namespace DI.Services
{
    public class InsecureDeserializationService : IInsecureDeserializationService
    {
        /*
         * Insecure Netwonsoft.JSON Deserialize usage
         */
        public void NewtonsoftDeserialization(string json)
        {
            try
            {
                JsonConvert.DeserializeObject<object>(json, new JsonSerializerSettings
                {
                    TypeNameHandling = TypeNameHandling.All
                });
            } catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure FastJSON Deserialize usage
         */
        public void FastJSONDeserialization(string json)
        {
            try
            {
                var obj = JSON.ToObject(json, new JSONParameters { BadListTypeChecking = false });
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure DataContractJsonSerializer Deserialize usage
         */
        public void DataContractJsonDeserialization(string type, string json)
        {
            DataContractJsonSerializerSettings dataContractJsonSerializerSettings = new DataContractJsonSerializerSettings()
            {
                KnownTypes = null
            };

            DataContractJsonSerializer dataContractJsonSerializer = new DataContractJsonSerializer(Type.GetType(type), dataContractJsonSerializerSettings);

            try
            {
                MemoryStream memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(json));
                dataContractJsonSerializer.ReadObject(memoryStream);
                memoryStream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure JavascriptSerializer Deserialize usage
         */
        public void JavascriptSerializerDeserialization(string json)
        {
            try
            {
                var serializer = new JavaScriptSerializer(new SimpleTypeResolver());
                serializer.DeserializeObject(json);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure BinaryFormatter usage
         * https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?view=net-5.0#remarks
         */
        public void BinaryFormatterDeserialization(string json)
        {
            try
            {
                BinaryFormatter binaryFormatter = new BinaryFormatter();

                MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(json));
                binaryFormatter.Deserialize(memoryStream);
                memoryStream.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure LosFormatter usage
         * https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.losformatter.deserialize?view=netframework-4.8#remarks
         */
        public void LosFormatterDeserialization(string json)
        {
            try
            {
                LosFormatter losFormatter = new LosFormatter();
                object obj = losFormatter.Deserialize(json);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure SoapFormatter usage
         * https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.soap.soapformatter.deserialize?view=netframework-4.8#remarks
         */
        public void SoapFormatterDeserialization(string json)
        {
            try
            {
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json));

                SoapFormatter soapFormatter = new SoapFormatter();
                object obj = soapFormatter.Deserialize(ms);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure NetDataContractSerializer usage
         * https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.netdatacontractserializer.deserialize?view=netframework-4.8#remarks
         */
        public void NetDataContractDeserialization(string json)
        {
            try
            {
                MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json));

                NetDataContractSerializer netDataContractSerializer = new NetDataContractSerializer();
                object obj = netDataContractSerializer.Deserialize(ms);
                Console.WriteLine(obj);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        /*
         * Insecure FsPickler Deserialize usage
         */
        public void FsPicklerDeserialization(string json)
        {
            try
            {
                var fsPickler = FsPickler.CreateJsonSerializer();
                MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(json));
                fsPickler.Deserialize<object>(memoryStream);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}

namespace DI.Services
{
    public class SqlInjectionService : ISqlInjectionService
    {
        private string GetConnectionString()
        {
            var connectionString = ConfigurationManager.ConnectionStrings["SqlExpress"].ConnectionString;

            return connectionString;
        }

        #region Union Based

        public string UnionBased(string param)
        {
            string result = "";
            string query = "SELECT * from [dbo].[USER] WHERE NAME = '" + param + "';";

            try
            {
                using (SqlConnection connection = new SqlConnection(
                   GetConnectionString()))
                    {
                        connection.Open();

                        SqlCommand command = new SqlCommand(query, connection);
                        SqlDataReader reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            result += String.Format("Username: {0} Role: {1}", reader["NAME"], reader["ROLE"]);
                        }
                    }
            } catch(Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        public string UnionBasedWithFormatString(string param)
        {
            string result = "";
            string query = String.Format("SELECT * from [dbo].[USER] WHERE NAME = '{0}';", param);

            try
            {
                using (SqlConnection connection = new SqlConnection(
                   GetConnectionString()))
                    {
                        connection.Open();

                        SqlCommand command = new SqlCommand(query, connection);
                        SqlDataReader reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            result += String.Format("Username: {0} Role: {1}", reader["NAME"], reader["ROLE"]);
                        }
                    }
            } catch(Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        public string UnionBasedWithSqlDataAdapter(string param)
        {
            string result = "";
            string query = "SELECT * from [dbo].[USER] WHERE NAME = '" + param + "';";

            try
            {
                SqlDataAdapter dataAdapter = new SqlDataAdapter(query, GetConnectionString());

                DataTable dt = new DataTable();

                dataAdapter.Fill(dt);

                foreach (DataRow row in dt.Rows)
                {
                    result += String.Format("Username: {0} Role: {1}", row["NAME"], row["ROLE"]);
                }
            }
            catch (Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        #endregion

        #region Error Based

        public string ErrorBased(string param)
        {
            string result;
            string query = "INSERT INTO [dbo].[PRODUCT] (NAME) VALUES ('" + param + "');";

            try
            {
                using (SqlConnection connection = new SqlConnection(
                   GetConnectionString()))
                    {
                        connection.Open();

                        SqlCommand command = new SqlCommand(query, connection);
                        SqlDataReader reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            System.Diagnostics.Debug.WriteLine(String.Format("{0}", reader[0]));
                        }
                    }

                result = "Product was added";

            } catch (Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        public string ErrorBasedWithFormatString(string param)
        {
            string result;
            string query = String.Format("INSERT INTO [dbo].[PRODUCT] (NAME) VALUES ('{0}');", param);

            try 
            {
                using (SqlConnection connection = new SqlConnection(
                   GetConnectionString()))
                    {
                        connection.Open();

                        SqlCommand command = new SqlCommand(query, connection);
                        SqlDataReader reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            System.Diagnostics.Debug.WriteLine(String.Format("{0}", reader[0]));
                        }
                    }

                result = "Product was added";

            } catch(Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        public string ErrorBasedWithSqlDataAdapter(string param)
        {
            string result;
            string query = "INSERT INTO [dbo].[PRODUCT] (NAME) VALUES ('" + param + "');";

            try 
            {
                SqlDataAdapter dataAdapter = new SqlDataAdapter(query, GetConnectionString());

                DataTable dt = new DataTable();
                dataAdapter.Fill(dt);

                foreach (DataRow row in dt.Rows)
                {
                    System.Diagnostics.Debug.WriteLine(row["Name"]);
                }

                result = "Product was added";

            } catch (Exception e)
            {
                result = e.Message;
            }

            return result;
        }

        #endregion
    }
}

// should not trigger any rules, this code is safe

using System;
using System.Data.SqlClient;

class Program
{
    static void Main()
    {
        string connectionString = "your_connection_string_here";
        string userInput = "user_input_here";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            connection.Open();

            string query = "SELECT * FROM Users WHERE FirstName = @FirstName";
            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@FirstName", userInput);

                using (SqlDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        Console.WriteLine($"ID: {reader["Id"]}, Name: {reader["FirstName"]}");
                    }
                }
            }
        }
    }
}
