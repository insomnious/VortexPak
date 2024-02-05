// See https://aka.ms/new-console-template for more information

using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.Diagnostics;
using System.Security.Cryptography;

namespace PakReader;

struct Footer
{
    public long footerOffset;
    public Guid encryptionKey; // 16
    public bool encrypedIndex;
    public int magic;
    public int version;
    public long indexOffset;
    public long indexSize;
    public string indexHash; // 20 bytes Hash of the unencrypted but padded Index
    public bool frozen;
    public string[] compressionMethods;
}

struct Index
{
    public int mountPointSize;
    public string mountPoint;
    public int entryCount;
    public ulong pathHashSeed;
    public bool hasPathHashIndex;
    public long pathHashIndexOffset;
    public long pathHashIndexSize;
    public byte[] pathHashIndexHash; // 20 bytes
    public bool hasFullDirectoryIndex;
    public long fullDirectoryIndexOffset;
    public long fullDirectoryIndexSize;
    public byte[] fullDirectoryIndexHash;
    public int encodedEntryInfoSize;
    public byte[] encodedEntryInfo; // size is above
    public uint fileCount;
    public byte[] records;
}

class Program
{
    
    private const int PAK_COMPRESSION_METHOD_SIZE = 32;
    private const int PAK_COMPRESSION_METHOD_COUNT = 5;
    private const int V8_PAK_COMPRESSION_METHOD_COUNT = 4;
    private const int PAK_ENCRYPTION_GUID_SIZE = 16;
    private const int INDEX_HASH_SIZE = 20;
    private const int PAK_BOOL_SIZE = 1;
    
    private const int MAGIC = 1517228769;
    
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("Sample command-line app")
        {
            new Argument<FileInfo>(name: "file", description: "PAK file to parse")
        };
            
        rootCommand.Handler = CommandHandler.Create<FileInfo>(ReadFile);
        
        return await rootCommand.InvokeAsync(args);
    }

    private static void ReadFile(FileInfo file)
    {
        /*
        if (!File.Exists(file.FullName))
        {
            Console.Error.Write("File doesn't exist");
            Environment.Exit(1);
        }*/
        
        try {
            using (var br = new BinaryReader(file.OpenRead()))
            {
                var version = FindFileVersion(br);

                if (version == 0)
                {
                    Console.Error.WriteLine("File version couldn't be found");
                    Environment.Exit(1);
                }
                
                Console.WriteLine($"File version is {version}");

                var footer = DecodeFooter(br, version);

                var index = DecodeVersion10Index(br, footer.indexOffset);

                DecodeFullDirectoryIndex(br, index.fullDirectoryIndexOffset);
                // 
            }

        }
        catch (FileNotFoundException fnfe)
        {
            // Exception handler for FileNotFoundException
            // We just inform the user that there is no such file
            Console.WriteLine("The file '{0}' is not found.", file);
        }
        catch (IOException ioe)
        {
            // Exception handler for other input/output exceptions
            // We just print the stack trace on the console
            Console.WriteLine(ioe.StackTrace);
        }
        catch (Exception ex)
        {
            // Exception handler for any other exception that may occur and was not already handled specifically
            // We print the entire exception on the console
            Console.WriteLine(ex.ToString());
        }
        
    }

    private static int FindFileVersion(BinaryReader br)
    {
        // start with the max offset for footer
        var pos = br.BaseStream.Length - 226;
                
        br.BaseStream.Seek(pos, 0);
                
        //
        while (br.BaseStream.Position < br.BaseStream.Length - 4)
        {
            // read int
            var magic = br.ReadInt32();
                    
            // compare this int with our magic int                    
            if (magic == MAGIC)
            {
                // version is next the byte after the magic in all versions of the pak format
                var version = br.ReadByte();
                //Console.WriteLine($"Found magic byte at position {pos} and version is {version}");
                return version;
            }
                    
            // advance position if magic isn't matched
            pos++;
                    
            // re-seek
            br.BaseStream.Seek(pos, 0);
        }

        return 0;
    }

    private static Footer DecodeFooter(BinaryReader br, int version)
    {
        var footerSize = GetFooterSize(version);
        
        Console.WriteLine($"Footer size is {footerSize}");


        return version switch
        {
            11 => DecodeVersion11Footer(br, footerSize),
            _ => new Footer()
        };
        
        
    }

    private static Index DecodeVersion10Index(BinaryReader br, long position)
    {
        br.BaseStream.Seek(position, SeekOrigin.Begin);

        var index = new Index();


        index.mountPointSize = br.ReadInt32();
        index.mountPoint = ReadNullTerminatedString(br);
        index.entryCount = br.ReadInt32();
        index.pathHashSeed = br.ReadUInt64();
        index.hasPathHashIndex = Convert.ToBoolean(br.ReadUInt32());

        if (index.hasPathHashIndex)
        {
            index.pathHashIndexOffset = br.ReadInt64();
            index.pathHashIndexSize = br.ReadInt64();
            index.pathHashIndexHash = br.ReadBytes(20);
        }

        index.hasFullDirectoryIndex = Convert.ToBoolean(br.ReadUInt32());
        
        if (index.hasFullDirectoryIndex)
        {
            index.fullDirectoryIndexOffset = br.ReadInt64();
            index.fullDirectoryIndexSize = br.ReadInt64();
            index.fullDirectoryIndexHash = br.ReadBytes(20);
        }

        index.encodedEntryInfoSize = br.ReadInt32();
        index.encodedEntryInfo = br.ReadBytes(index.encodedEntryInfoSize);
        index.fileCount = br.ReadUInt32();

        return index;
    }

    private static void DecodeFullDirectoryIndex(BinaryReader br, long position)
    {
        br.BaseStream.Seek(position, SeekOrigin.Begin);

        uint directoryCount = br.ReadUInt32();
        Console.WriteLine($"DirectoryCount {directoryCount}");

        for (int i = 0; i < directoryCount; i++)
        {
            int directoryNameSize = br.ReadInt32();
            string directoryName = ReadNullTerminatedString(br);
            uint fileCount = br.ReadUInt32();

            for (int j = 0; j < fileCount; j++)
            {
                int filenameSize = br.ReadInt32();
                string filename = ReadNullTerminatedString(br);
                uint encodedEntryInfoOffset = br.ReadUInt32();
                
                Console.WriteLine($"{directoryName}{filename} offset={encodedEntryInfoOffset}");
            }
            
            
        }



    }
    
    private static Footer DecodeVersion11Footer(BinaryReader br, long position)
    {
        br.BaseStream.Seek(br.BaseStream.Length - position, SeekOrigin.Begin);
        
        var footer = new Footer
        {
            footerOffset = br.BaseStream.Position,
            encryptionKey = new Guid(br.ReadBytes(16)),
            encrypedIndex = BitConverter.ToBoolean(br.ReadBytes(1)),
            magic = br.ReadInt32(),
            version = br.ReadInt32(),
            indexOffset = br.ReadInt64(),
            indexSize = br.ReadInt64(),
            indexHash = BitConverter.ToString(br.ReadBytes(20)).Replace("-", "")
        };
        
        Console.WriteLine(br.BaseStream.Position);

        List<string> compressionMethodsList = new List<string>();

        for (int i = 0; i < PAK_COMPRESSION_METHOD_COUNT; i++)
        {
            compressionMethodsList.Add(ReadNullTerminatedString(br));
        }

        footer.compressionMethods = compressionMethodsList.ToArray();
        
        return footer;
    }
    


    private static long GetFooterSize(int version)
    {
        // always the same in every version
        var magic = sizeof(int);
        var versionSize = sizeof(int);
        var indexOffsetSize = sizeof(long);
        var indexSize = sizeof(long);
        var indexSha1Size = INDEX_HASH_SIZE;
        var size = magic + versionSize + indexOffsetSize + indexSize + indexSha1Size;
        
        // Version >= 4 has encrypted index flag
        if (version >= 4) {
            size += PAK_BOOL_SIZE;
        }

        // Version 7 has encryption key guid
        if (version >= 7) {
            size += PAK_ENCRYPTION_GUID_SIZE;
        }

        // Version 8 has Compression method
        if (version == 8) {
            size += V8_PAK_COMPRESSION_METHOD_COUNT * PAK_COMPRESSION_METHOD_SIZE;
        } else if (version > 8) {
            size += PAK_COMPRESSION_METHOD_COUNT * PAK_COMPRESSION_METHOD_SIZE;
        }

        // Version 9 has frozen index flag and version 10 upwards does not
        if (version == 9) {
            size += PAK_BOOL_SIZE;
        }

        return size;
    }
    
    public static string ReadNullTerminatedString(BinaryReader br)
    {
        string str = "";
        char ch;
        while ((int)(ch = br.ReadChar()) != 0)
            str = str + ch;
        return str;
    }
}

