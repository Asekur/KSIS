using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Traceroute
{
    class Program
    {
        static void Traceroute(String host, bool dnsFlag)
        {
            try
            {
                byte[] receivedData = new byte[1024];
                int receivedSize = 0;
                IPEndPoint iep = null;
                EndPoint ep = null;
                try
                {
                    //Return IP adress
                    iep = new IPEndPoint(Dns.GetHostAddresses(host)[0], 0);
                    ep = (EndPoint)iep;
                }
                catch
                {
                    Console.WriteLine("Host unreachable");
                    throw;
                }
                Socket socket = new Socket(iep.AddressFamily, SocketType.Raw, ProtocolType.Icmp);
                ICMP packet = new ICMP(8, 0, Encoding.ASCII.GetBytes("Angelina"));

                //Assign settings for new socket
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                bool isFinished = false;
                Console.WriteLine("Traceroute with a maximum number of hops 30: ");
                for (int i = 0; i < 30; i++)
                {
                    //Assign ttl for socket
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, i + 1);
                    Console.Write("{0:d2}    ", i + 1);
                    string transitHost = null;
                    int routerUnresponding = 0;

                    //Run traceroute 3 attempts
                    for (int k = 0; k < 3; k++)
                    {

                        //Time for package arrival
                        DateTime timeStart = DateTime.Now;
                        //Sending bytes on IP address
                        socket.SendTo(packet.getBytesOfPackage(), SocketFlags.None, iep);
                        try
                        {
                            //"ref" - transfer by reference (without changing the variable)
                            receivedSize = socket.ReceiveFrom(receivedData, ref ep);
                            TimeSpan time = DateTime.Now - timeStart;

                            //ICMP package reply
                            ICMP response = new ICMP(receivedData, receivedSize);

                            //TTL exceeded
                            if (response.Type == 11)
                            {
                                if (transitHost == null)
                                {
                                    transitHost = ep.ToString();
                                }
                                Console.Write("{0:d3} ms   ", (time.Milliseconds));
                                if (k == 2 && i == 29)
                                {
                                    Console.WriteLine("Numper of hops exceeded.");
                                }
                            }

                            //Echo request
                            if (response.Type == 0)
                            {
                                Console.Write("{0:d3} ms   ", (time.Milliseconds));
                                isFinished = true;
                            }
                        }
                        catch (SocketException)
                        {
                            Console.Write("     *   ");
                            routerUnresponding++;
                            if (routerUnresponding == 3)
                            {
                                Console.WriteLine("Request tined out.");
                            }
                            if (k == 2 && i == 29)
                            {
                                Console.WriteLine("Numper of hops exceeded.");
                            }
                        }
                    }
                    if (transitHost != null)
                    {
                        transitHost = transitHost.Remove(transitHost.IndexOf(':'));
                        Console.Write(transitHost);
                        //Determine name
                        if (dnsFlag)
                        {
                            try
                            {
                                Console.WriteLine(" [" + Dns.GetHostEntry(transitHost).HostName + "] ");
                            }
                            catch
                            {
                                Console.WriteLine();
                            }
                        }
                    }
                    if (isFinished)
                    {
                        string cutIEP = iep.ToString().Remove(iep.ToString().IndexOf(':'));
                        Console.Write(cutIEP);
                        //Determine name
                        if (dnsFlag)
                        {
                            try
                            {
                                Console.WriteLine(" [" + Dns.GetHostEntry(cutIEP).HostName + "] ");
                            }
                            catch
                            {
                                Console.WriteLine();
                            }
                        }
                        Console.WriteLine("Traceroute completed.");
                        break;
                    }
                }
                socket.Close();
            }
            catch
            {
                Console.WriteLine("Error, sorry :(");
            }

        }

        static void Main(string[] argv)
        {
            bool dnsFlag = argv[0] == "+d" ? true : false;
            Traceroute(argv[0] == "+d" ? argv[1] : argv[0], dnsFlag);
        }
    }



    //Create ICMP package
    class ICMP
    {
        public byte Type;
        public byte Code;
        public UInt16 Checksum;
        public UInt32 DataSize;
        public byte[] Data;

        //Request ICMP package
        public ICMP(Byte type, Byte code, params Byte[] data)
        {
            Type = type;
            Code = code;
            DataSize = (UInt32)data.Length;
            Data = new byte[DataSize];
            Buffer.BlockCopy(data, 0, Data, 0, data.Length);
            Checksum = getChecksum();
        }


        //Reply ICMP package
        public ICMP(byte[] receivedPacket, int size)
        {
            Type = receivedPacket[20];
            Code = receivedPacket[21];
            Checksum = BitConverter.ToUInt16(receivedPacket, 22);
            DataSize = (UInt32)size - 24;
            Data = new byte[DataSize];
            Buffer.BlockCopy(receivedPacket, 24, Data, 0, (int)DataSize);
        }

        public byte[] getBytesOfPackage()
        {
            byte[] data = new byte[DataSize + 4];
            Buffer.BlockCopy(BitConverter.GetBytes(Type), 0, data, 0, 1);
            Buffer.BlockCopy(BitConverter.GetBytes(Code), 0, data, 1, 1);
            Buffer.BlockCopy(BitConverter.GetBytes(Checksum), 0, data, 2, 2);
            Buffer.BlockCopy(Data, 0, data, 4, (int)DataSize);
            return data;
        }

        public UInt16 getChecksum()
        {
            UInt32 checkSum = 0;

            //Data = array of ICMP package as bytes
            byte[] data = getBytesOfPackage();
            int packagesize = (int)DataSize + 4;
            int indexOfBytes = 0;
            while (indexOfBytes < packagesize)
            {
                checkSum += Convert.ToUInt32(BitConverter.ToUInt16(data, indexOfBytes));
                indexOfBytes += 2;
            }

            //Conversion of checkSum
            checkSum = (checkSum >> 16) + (checkSum & 0xffff);
            checkSum += (checkSum >> 16);
            return (UInt16)(~checkSum);
        }
    }
}

