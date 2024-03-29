﻿// See https://aka.ms/new-console-template for more information

using System.Collections;
using System.Collections.Specialized;
using System.CommandLine;
using System.CommandLine.NamingConventionBinder;
using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ICSharpCode.SharpZipLib.Zip.Compression;
using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using NLog;
using Oodle.NET;

namespace PakReader;

 
/// <summary>
/// Specifies the number of bits in the bit field structure
/// Maximum number of bits are 64
/// </summary>
[AttributeUsage(AttributeTargets.Struct | AttributeTargets.Class, AllowMultiple = false)]
public sealed class BitFieldNumberOfBitsAttribute : Attribute
{
    /// <summary>
    /// Initializes new instance of BitFieldNumberOfBitsAttribute with the specified number of bits
    /// </summary>
    /// <param name="bitCount">The number of bits the bit field will contain (Max 64)</param>
    public BitFieldNumberOfBitsAttribute(byte bitCount)
    {
        if ((bitCount < 1) || (bitCount > 64))
            throw new ArgumentOutOfRangeException("bitCount", bitCount, 
                "The number of bits must be between 1 and 64.");

        BitCount = bitCount;
    }

    /// <summary>
    /// The number of bits the bit field will contain
    /// </summary>
    public byte BitCount { get; private set; }
}

/// <summary>
/// Specifies the length of each bit field
/// </summary>
[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false)]
public sealed class BitFieldInfoAttribute : Attribute
{
    /// <summary>
    /// Initializes new instance of BitFieldInfoAttribute with the specified field offset and length
    /// </summary>
    /// <param name="offset">The offset of the bit field</param>
    /// <param name="length">The number of bits the bit field occupies</param>
    public BitFieldInfoAttribute(byte offset, byte length)
    {
        Offset = offset;
        Length = length;
    }

    /// <summary>
    /// The offset of the bit field
    /// </summary>
    public byte Offset { get; private set; }

    /// <summary>
    /// The number of bits the bit field occupies
    /// </summary>
    public byte Length { get; private set; }
}

/// <summary>
/// Interface used as a marker in order to create extension methods on a struct
/// that is used to emulate bit fields
/// </summary>
public interface IBitField { }

[BitFieldNumberOfBitsAttribute(32)]
struct InfoBitfield : IBitField
{        
    [BitFieldInfo(0, 6)]
    public uint CompressionBlockSize { get; set; }
        
    [BitFieldInfo(6, 16)]
    public uint CompressionBlockCount { get; set; }
        
    [BitFieldInfo(22, 1)]
    public bool IsEncrypted { get; set; }
        
    [BitFieldInfo(23, 6)]
    public uint CompressionMethod { get; set; }
        
    [BitFieldInfo(29, 1)]
    public bool IsSize32BitSafe { get; set; }
        
    [BitFieldInfo(30, 1)]
    public bool IsUncompressedSize32BitSafe { get; set; }
        
    [BitFieldInfo(31, 1)]
    public bool IsOffset32BitSafe { get; set; }
}

public class PakException : Exception
{
    public PakException(string message) : base(message)
    {
        
    }
}

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
    public bool frozenIndex;
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
    public string pathHashIndexHash; // 20 bytes
    public bool hasFullDirectoryIndex;
    public long fullDirectoryIndexOffset;
    public long fullDirectoryIndexSize;
    public string fullDirectoryIndexHash;
    public int encodedEntryInfoSize;
    [JsonIgnore]
    public byte[] encodedEntryInfo; // size is above
    public int recordCount;
    public IndexRecord[] indexRecords; 
}

struct IndexRecord
{
    public uint filenameSize;
    public string filename;
    public Record fileMetadata;
    public DataRecord dataRecord;
    public string fullpath;
}

struct DataRecord
{
    public Record fileMetadata;
    public long dataOffset;
    [JsonIgnore]
    public byte[] fileData;
}

struct CompressionBlock
{
    /*
 * compressed data block start offset.
                       version <= 4: offset is absolute to the file
                       version 7: offset is relative to the offset
                                  field in the corresponding Record
 */
    public long startOffset; 

    /*compressed data block end offset.
                           There may or may not be a gap between blocks.
                           version <= 4: offset is absolute to the file
                           version 7: offset is relative to the offset
                                      field in the corresponding Record
                                      */
    public long endOffset;
}
    
struct Record
{
    public long offset; // 8
    public long size; // 8
    public long uncompressedSize; // 8
    /*
        0x00 ... none
        0x01 ... zlib
        0x10 ... bias memory
        0x20 ... bias speed
     */
    public uint compressionMethod; // 4
    public ulong timestamp; // version 1
    public string dataHash; //sha1 hash // 20 // compressed data hash, not decompressed
    // if compressed
    public uint blockCount; // 4
    public CompressionBlock[] compressionBlocks; // 16 * blockCount
    
    public bool isEncrypted; // 1
    public uint compressionBlockUncompressedSize; // 4
}
    
struct FullDirectoryIndex
{    
    public uint directoryCount;
    public Directory[] directories;
}

struct Directory
{
    public int directoryNameSize;
    public string directoryName;
    public uint fileCount;
    public File[] files;
}

struct File
{
    public int filenameSize;
    public string filename;
    public uint encodedEntryInfoOffset;
    public EncodedRecord encodedRecord;
    public DataRecord dataRecord;
    public string fullpath;
}

struct EncodedRecord
{
    /* 0-5  : Compression block size
                              6-21 : Compression blocks count
                              22   : Encrypted
                              23-28: Compression method
                              29   : Size 32-bit safe?
                              30   : Uncompressed size 32-bit safe?
                              31   : Offset 32-bit safe?*/
    public InfoBitfield info; // bitfield
    public ulong offset;
    public ulong uncompressedSize;
    public ulong size;
    public uint blockSize;
}

struct PakFile
{
    public string filename;
    public Footer footer;
    public Index index;
    public FullDirectoryIndex fullDirectoryIndex;
    public string[] normalizedFilePaths;
}

[JsonConverter(typeof(StringEnumConverter))]
enum ModType
{
    None,
    Regular,
    Blueprint
}

struct Summary
{
    public string filePath;
    public bool encrypted;
    public int pakVersion;
    public int fileCount;
    public string mountPoint;
    public string normalizedMountPoint;
    public TimeSpan timeTaken;
    public ModType modType;
    public string blueprintModName;
}


struct ModMetaData
{
    public string blueprintModName;
    public ModType modType;
}

class Program
{
    private static Logger logger;

    private const int PAK_COMPRESSION_METHOD_SIZE = 32;
    private const int PAK_COMPRESSION_METHOD_COUNT = 5;
    private const int PAK_COMPRESSION_METHOD_COUNT_V8 = 4;
    private const int PAK_ENCRYPTION_GUID_SIZE = 16;
    private const int INDEX_HASH_SIZE = 20;
    private const int PAK_BOOL_SIZE = 1;
    private const long FOOTER_SEARCH_SIZE = 226; // offset from the bottom to start the search for the magic
    private const int MAX_SUPPORTED_VERSION = 11;

    private const int MAGIC = 1517228769;

    
    static async Task<int> Main(string[] args)
    {
        var extractOption = new Option<Boolean>(new[] { "--extract", "-e" }, () => false, "Extract PAK file contents");
        var jsonOption = new Option<Boolean>(new[] { "--json", "-j" }, () => false, "Write JSON metadata file");
        var debugOption = new Option<Boolean>(new[] { "--debug", "-d" }, () => false, "Debug output");
        var modOption = new Option<Boolean>(new[] { "--mod", "-m" }, () => false, "Extra analysis if a mod PAK file");
        var fileArgument = new Argument<FileInfo>(name: "file", description: "PAK file to parse");
        
        var rootCommand = new RootCommand("Sample command-line app")
        {
            fileArgument,
            extractOption,
            jsonOption,
            debugOption,
            modOption
        };

        rootCommand.SetHandler(ReadFile, fileArgument, extractOption, jsonOption, debugOption, modOption);

        // logging stuff
        
        // create a configuration instance
        var config = new NLog.Config.LoggingConfiguration();

        // create a console logging target
        var logConsole = new NLog.Targets.ConsoleTarget();

        var debugConsole = new NLog.Targets.DebugSystemTarget();

        // send logs with levels from Info to Fatal to the console
        config.AddRule(NLog.LogLevel.Warn, NLog.LogLevel.Fatal, logConsole);
        // send logs with levels from Debug to Fatal to the console
        config.AddRule(NLog.LogLevel.Debug, NLog.LogLevel.Fatal, debugConsole);

        // apply the configuration
        LogManager.Configuration = config;

        // create a logger
        logger = LogManager.GetCurrentClassLogger();
        
        return await rootCommand.InvokeAsync(args);
    }

    private static void ReadFile(FileInfo file, bool extractOption, bool jsonOption, bool debugOption, bool modOption)
    {
        Stopwatch sw = new Stopwatch();
        sw.Start();
        
        logger.Info("VortexPak Started");
        logger.Debug($"fileArgument={file.FullName}");
        logger.Debug($"extractOption={extractOption}");
        logger.Debug($"jsonOption={jsonOption}");
        logger.Debug($"debugOption={debugOption}");
        logger.Debug($"modOption={modOption}");
        
        try
        {
            using var br = new BinaryReader(file.OpenRead());
            
            var version = FindFileVersion(br);

            if (version == 0 || version > MAX_SUPPORTED_VERSION)
            {
                throw new PakException($"Not a valid PAK file. Version not supported.");
            }
            
            logger.Info($"File version is {version}");

            var pakFile = ReadPak(br, version);
            pakFile.filename = Path.GetFileName(file.FullName);
                
            logger.Info($"Indexing complete in {sw.Elapsed:hh\\:mm\\:ss\\.ffff}");

            var outputFolder = Path.Join("C:\\", Path.GetFileNameWithoutExtension(file.FullName));
            
            var summary = new Summary
            {
                encrypted = pakFile.footer.encrypedIndex,
                pakVersion = version,
                fileCount = pakFile.index.hasFullDirectoryIndex ? pakFile.index.entryCount : pakFile.index.recordCount,
                mountPoint = pakFile.index.mountPoint,
                normalizedMountPoint = NormalizePath(pakFile.index.mountPoint),
                filePath = file.FullName,
                timeTaken = sw.Elapsed
            };
            
            if (modOption)
            {
                logger.Debug("Mod analysis option. Analyzing mod type.");
                var modMeta = AnalyzeMod(pakFile);

                summary.modType = modMeta.modType;
                summary.blueprintModName = modMeta.blueprintModName;
            }
            
            if (jsonOption)
            {
                logger.Debug("Json output option. Writing metadata file.");
                
                Stopwatch jsonSw = new Stopwatch();
                jsonSw.Start();
                var json = JsonConvert.SerializeObject(pakFile, Formatting.Indented);
                var jsonOutput = Path.ChangeExtension(file.FullName, ".json");
                System.IO.File.WriteAllText(jsonOutput, json);
                jsonSw.Stop();
                
                logger.Info($"{jsonOutput} written in {jsonSw.Elapsed:hh\\:mm\\:ss\\.ffff} seconds");
            }

            if (extractOption)
            {
                logger.Info($"Extract option is enabled. Extracting files to {outputFolder}");
                
                if(pakFile.index.hasFullDirectoryIndex)
                {
                    logger.Debug("This file contains a full directory index");

                    ExtractFromFullDirectory(br, pakFile.index, pakFile.fullDirectoryIndex, outputFolder);
                }
                else
                {
                    logger.Debug("This file contains the legacy index record");

                    ExtractFromIndex(br, pakFile.index, outputFolder);
                }
                
                logger.Info($"Extraction completed in {sw.Elapsed:hh\\:mm\\:ss\\.ffff}");
            }
            else
            {
                logger.Info($"Completed in {sw.Elapsed:hh\\:mm\\:ss\\.ffff}");
            }
            
            
            Console.WriteLine(JsonConvert.SerializeObject(summary, Formatting.None, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            }));
            
        }
        catch (FileNotFoundException fnfe)
        {
            // Exception handler for FileNotFoundException
            // We just inform the user that there is no such file
            logger.Error("The file '{0}' is not found.", file);
        }
        catch (PakException pex)
        {
            // Exception handler for PakException
            // We just inform the user with the message
            logger.Error(pex.Message);
        }
        catch (IOException ioe)
        {
            // Exception handler for other input/output exceptions
            logger.Error(ioe.StackTrace);
        }
        catch (Exception ex)
        {
            // Exception handler for any other exception that may occur and was not already handled specifically
            logger.Error(ex.ToString());
        }

    }

    private static ModMetaData AnalyzeMod(PakFile pakFile, bool debug = false)
    {
        // do something with file paths
        // look for a Mods folder in one of the paths, if it exists then we return blueprint type, if not, regular type
        
        foreach (var path in pakFile.normalizedFilePaths)
        {
            var directories = path.Split("\\");

            var modsIndex = Array.IndexOf(directories, "Mods", 0);

            if (modsIndex == -1) continue;
            
            logger.Debug($"Found Mods folder in {path}. This is a blueprint mod. Mod name is {directories[modsIndex + 1]}");

            return new ModMetaData { modType = ModType.Blueprint, blueprintModName = directories[modsIndex + 1] };
        }

        return new ModMetaData { modType = ModType.Regular, blueprintModName = ""};
    }

    private static string NormalizePath(string filePath)
    {
        string trimmed = filePath.Replace("/", Path.DirectorySeparatorChar.ToString());
        string[] segments = trimmed.Split(Path.DirectorySeparatorChar);
        List<string> normal = new List<string>();

        foreach (string segment in segments)
        {
            if ( segment != "" && segment != "." && segment != "..")
            {
                normal.Add(segment);
            }
        }

        return string.Join(Path.DirectorySeparatorChar, normal);
    }

    private static void ExtractFromIndex(BinaryReader br, Index index, string outputFolder)
    {
        foreach (var record in index.indexRecords)
        {
            //string outfile = Path.GetFullPath(Path.Combine(outputFolder , $"{index.mountPoint}{record.filename}"));
            string normalizedPath = NormalizePath($"{index.mountPoint}{record.filename}");
            string outfile = Path.GetFullPath(Path.Combine(outputFolder, normalizedPath));
            //Console.WriteLine($"Outfile: {outfile}");
            
            Stopwatch sw = new Stopwatch();
            sw.Start();
                
            //byte[] bytes = GetBytesFromPak(br, file.dataRecord, $"{index.mountPoint}{dir.directoryName}{file.filename}", true);
            //GetBytesFromPak(br, file.dataRecord, $"{index.mountPoint}{dir.directoryName}{file.filename}", outfile, true);
                    
               
            //byte[] bytes = GetBytesFromPak(br, record.dataRecord, $"{index.mountPoint}{record.filename}");
            GetBytesFromPak(br, record.dataRecord, $"{index.mountPoint}{record.filename}", outfile);
            
            logger.Debug($"{outfile} ({record.fileMetadata.uncompressedSize:n0} bytes) written in {sw.Elapsed:ss\\.ffff} seconds");
            
            //(new FileInfo(outfile)).Directory.Create();
            //System.IO.File.WriteAllBytes(outfile, bytes);
            
        }
    }
    
    private static void ExtractFromFullDirectory(BinaryReader br, Index index, FullDirectoryIndex fullDirectoryIndex, string outputFolder)
    {
        foreach (var dir in fullDirectoryIndex.directories)
        {
            foreach (var file in dir.files)
            {
                string outfile = Path.GetFullPath(Path.Combine(outputFolder, $"{dir.directoryName}{file.filename}"));
                
                Stopwatch sw = new Stopwatch();
                sw.Start();
                
                //byte[] bytes = GetBytesFromPak(br, file.dataRecord, $"{index.mountPoint}{dir.directoryName}{file.filename}", true);
                GetBytesFromPak(br, file.dataRecord, $"{index.mountPoint}{dir.directoryName}{file.filename}", outfile, true);
                    
                logger.Debug($"{outfile} ({file.dataRecord.fileMetadata.uncompressedSize:n0} bytes) written in {sw.Elapsed:ss\\.ffff} seconds");
                //(new FileInfo(outfile)).Directory.Create();
                //System.IO.File.WriteAllBytes(outfile, bytes);
            }
        }

    }

    private static void GetBytesFromPak(BinaryReader br, DataRecord dataRecord, string path, string outfile, bool useOodle = false)
    {
        if (dataRecord.fileMetadata.compressionMethod == 0)
        {
            //Console.WriteLine($"{path} is uncompressed");

            long offset = dataRecord.dataOffset;
            long size = dataRecord.fileMetadata.size;

            br.BaseStream.Seek(offset, SeekOrigin.Begin);
            
            if (System.IO.File.Exists(outfile))
            {
                System.IO.File.Delete(outfile);
            }
            
            AppendAllBytes(outfile, br.ReadBytes((int)size));
            
            //return br.ReadBytes((int)size);
            return;
        }

        //Console.WriteLine($"{path} is compressed. This has {dataRecord.fileMetadata.blockCount} blocks.");
        
        // get complete compressed data
        
        var compressed = new byte[dataRecord.fileMetadata.size];
        //var decompressed = new byte[dataRecord.fileMetadata.uncompressedSize];
        byte[] decompressed;

        //using var decompressedStream = new MemoryStream();
        
        // remove file if it exists so we can write it in blocks where necessary
        if (System.IO.File.Exists(outfile))
        {
            System.IO.File.Delete(outfile);
        }
        
        for (int i = 0; i < dataRecord.fileMetadata.compressionBlocks.Length; i++)
        {
            var block = dataRecord.fileMetadata.compressionBlocks[i];

            //Console.WriteLine($"  [{i:D5}] start: {block.startOffset} end: {block.endOffset} size: {block.endOffset - block.startOffset}");

            var offset = block.startOffset;
            var size = block.endOffset - block.startOffset;

            br.BaseStream.Seek(offset, SeekOrigin.Begin);

            byte[] blockData = br.ReadBytes((int)size);

            if (blockData == null) // Handle end of stream
                break;

            var decompressedBlock = useOodle ? OodleDecompress(blockData, (int) dataRecord.fileMetadata.compressionBlockUncompressedSize) : ZLibDecompress(blockData);
            

            // Append block data to buffer
            //decompressedStream.Write(decompressedBlock, 0, decompressedBlock.Length);
            
            AppendAllBytes(outfile, decompressedBlock);
            
        }
            
        //decompressed = Decompress(ms);
        //decompressed = decompressedStream.ToArray();

        //System.IO.File.WriteAllBytes(@"C:\Pal\dump.bin", compressed);

        //decompressed = ChunkedDecompress(compressed);

        //return decompressed;
    }
    
    private static void AppendAllBytes(string path, byte[] bytes)
    {
        (new FileInfo(path)).Directory.Create();

        //argument-checking here.

        using var stream = new FileStream(path, FileMode.Append);
        stream.Write(bytes, 0, bytes.Length);
    }
    
    private static unsafe byte[] OodleDecompress(byte[] compressedBuffer, int decompressedSize)
    {
        using var oodle = new OodleCompressor(Path.Join(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "oo2core_9_win64.dll"));
        //var compressedBuffer = System.IO.File.ReadAllBytes(@"C:\Test\Example.bin");
        var decompressedBuffer = new byte[decompressedSize];
        var result = oodle.DecompressBuffer(compressedBuffer, compressedBuffer.Length, decompressedBuffer,
            decompressedSize, OodleLZ_FuzzSafe.No, OodleLZ_CheckCRC.No, OodleLZ_Verbosity.None, 0L, 0L, 0L, 0L, 0L, 0L,
            OodleLZ_Decode_ThreadPhase.Unthreaded);
        return decompressedBuffer;
    }
    
    public static byte[] ZLibDecompress(byte[] zLibCompressedBuffer)
    {
        byte[] resBuffer = null;

        MemoryStream mInStream = new MemoryStream(zLibCompressedBuffer);
        MemoryStream mOutStream = new MemoryStream(zLibCompressedBuffer.Length);
        InflaterInputStream infStream = new InflaterInputStream(mInStream);

        mInStream.Position = 0;

        try
        {
            byte[] tmpBuffer = new byte[zLibCompressedBuffer.Length];
            int read = 0;

            do
            {
                read = infStream.Read(tmpBuffer, 0, tmpBuffer.Length);
                if (read > 0)
                    mOutStream.Write(tmpBuffer, 0, read);

            } while (read > 0);

            resBuffer = mOutStream.ToArray();
        }
        finally
        {
            infStream.Close();
            mInStream.Close();
            mOutStream.Close();
        }

        return resBuffer;
    }
    
    
   
    private static PakFile ReadPak(BinaryReader br, int version, bool debug = false)
    {
        var footer = ReadFooter(br, version);
        var index = ReadIndex(br, version, footer.indexOffset);
        var fullDirectoryIndex = new FullDirectoryIndex();
        
        var normalizedFilePaths = new List<string>();

        if (index.hasFullDirectoryIndex)
        {
            logger.Debug("This file contains a full directory index");
            
            // version 10 or above is confirmed and we need to go get the newer
            // folder/file data
            fullDirectoryIndex = ReadFullDirectoryIndex(br, index.fullDirectoryIndexOffset);
            
            MemoryStream ms = new MemoryStream(index.encodedEntryInfo);
            BinaryReader reader = new BinaryReader(ms);
            
            var flatFileList = new List<File>();
            
            // loop through the index
            for (var i = 0; i < fullDirectoryIndex.directories.Length; i++)
            {
                var dir = fullDirectoryIndex.directories[i];

                for (var j = 0; j < dir.files.Length; j++)
                {
                    var file = dir.files[j];

                    file.fullpath = $"{index.mountPoint}{dir.directoryName}{file.filename}";

                    reader.BaseStream.Seek(file.encodedEntryInfoOffset, SeekOrigin.Begin);

                    var encodedRecord = new EncodedRecord();

                    // Grab the big bitfield value:
                    // Bit 31 = Offset 32-bit safe?
                    // Bit 30 = Uncompressed size 32-bit safe?
                    // Bit 29 = Size 32-bit safe?
                    // Bits 28-23 = Compression method
                    // Bit 22 = Encrypted
                    // Bits 21-6 = Compression blocks count
                    // Bits 5-0 = Compression block size

                    //var rawBytes = reader.ReadBytes(4);
                    var intValue = reader.ReadInt32();
                    //BitArray bitArray = new BitArray(BitConverter.ToInt32(rawBytes));
                    //bool firstBit = bitArray[0];

                    encodedRecord.info = CreateBitField<InfoBitfield>((ulong)intValue);

                    encodedRecord.offset = encodedRecord.info.IsOffset32BitSafe 
                        ? reader.ReadUInt32() 
                        : reader.ReadUInt64();
                    
                    encodedRecord.uncompressedSize = encodedRecord.info.IsUncompressedSize32BitSafe
                        ? reader.ReadUInt32()
                        : reader.ReadUInt64();

                    if (encodedRecord.info.CompressionMethod != 0)
                    {
                        encodedRecord.size = encodedRecord.info.IsSize32BitSafe
                        ? reader.ReadUInt32()
                        : reader.ReadUInt64();
                    }
                    else
                    {
                        encodedRecord.size = (uint)encodedRecord.uncompressedSize;
                    }

                    /*
                    if (encodedRecord.info.CompressionBlockCount > 0 && (encodedRecord.info.IsEncrypted || encodedRecord.info.CompressionBlockCount != 1))
                    {
                        encodedRecord.blockSize = reader.ReadUInt32();
                    }*/

                    file.encodedRecord = encodedRecord;

                    // get data record?

                    file.dataRecord = GetDataRecord(br, version, (long)encodedRecord.offset);
                    
                    flatFileList.Add(file);
                    
                    dir.files[j] = file;
                    
                    
                    /*
                     * if compression block count > 0 && (encrypted || compression block count != 1)
                          for _ in 0..compression block count
                             ?     4  uint32_t     block size
                          end
                        end
                     */
                }
            }

            reader.Close();
            ms.Close();
            
            // clean output

            foreach (var file in flatFileList)  
            {
                var path = NormalizePath(file.fullpath);
                logger.Debug($"File: {path}");
                normalizedFilePaths.Add(path);
            }
            
            
        }
        else
        {
            logger.Debug("This file contains the legacy index record");

            // clean output
            foreach (var record in index.indexRecords)
            {
                var path = NormalizePath(record.fullpath);
                logger.Debug($"File: {path}");
                normalizedFilePaths.Add(path);
            }
        }
                
        var pakFile = new PakFile
        {
            index = index,
            fullDirectoryIndex = fullDirectoryIndex,
            footer = footer,
            normalizedFilePaths = normalizedFilePaths.ToArray()
        };

        return pakFile;
    }
    
    /// <summary>
    /// Creates a new instance of the provided struct.
    /// </summary>
    /// <typeparam name="T">The type of the struct that is to be created.</typeparam>
    /// <param name="value">The initial value of the struct.</param>
    /// <returns>The instance of the new struct.</returns>
    private static T CreateBitField<T>(ulong value) where T : struct
    {
        // The created struct has to be boxed, otherwise PropertyInfo.SetValue
        // will work on a copy instead of the actual object
        object boxedValue = new T();

        // Loop through the properties and set a value to each one
        foreach (PropertyInfo pi in boxedValue.GetType().GetProperties())
        {
            BitFieldInfoAttribute bitField;
            bitField = (pi.GetCustomAttribute(typeof(BitFieldInfoAttribute)) as BitFieldInfoAttribute);
            if (bitField != null)
            {
                ulong mask = (ulong)Math.Pow(2, bitField.Length) - 1;
                object setVal = Convert.ChangeType((value >> bitField.Offset) & mask, pi.PropertyType);
                pi.SetValue(boxedValue, setVal);
            }
        }
        // Unboxing the object
        return (T)boxedValue;
    }

    private static int FindFileVersion(BinaryReader br)
    {
        if(br.BaseStream.Length < FOOTER_SEARCH_SIZE)
        {
            throw new PakException($"Not a valid PAK file. File is too small.");
        }
        
        // start with the max offset for footer
        var pos = br.BaseStream.Length - FOOTER_SEARCH_SIZE;

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
        
        throw new PakException($"Not a valid PAK file. Magic byte not found.");
    }

    private static Footer ReadFooter(BinaryReader br, int version)
    {
        var footerSize = GetFooterSize(version);

        logger.Debug($"Footer size is {footerSize}");
        
        /*
         * v1-v3 = 44 !
         * v4-v6 = 45
         * v7 = 65
         * v8 = 221 !
         * v9 = 226
         * v10-v11 = 221 !
         */
        
        br.BaseStream.Seek(br.BaseStream.Length - footerSize, SeekOrigin.Begin);

        var footer = new Footer
        {
            footerOffset = br.BaseStream.Position
        };

        if(version >= 7) footer.encryptionKey = new Guid(br.ReadBytes(16));
        
        if(version >= 4) footer.encrypedIndex = BitConverter.ToBoolean(br.ReadBytes(1));
        
        // all versions
        footer.magic = br.ReadInt32();
        footer.version = br.ReadInt32();
        footer.indexOffset = br.ReadInt64();
        footer.indexSize = br.ReadInt64();
        footer.indexHash = BitConverter.ToString(br.ReadBytes(20)).Replace("-", string.Empty);
        
        // only version 9
        if(version == 9) footer.frozenIndex = BitConverter.ToBoolean(br.ReadBytes(1));

        List<string> compressionMethodsList = new List<string>();  
       
        // versions greater than 8 has compression methods as a string array.
        // unconfirmed but version 8 supposedly max array of 4, and version greater than
        // 8 has 5
        if ( version > 8)
        {
            for (int i = 0; i < PAK_COMPRESSION_METHOD_COUNT; i++)
            {
                if(br.PeekChar() == 0) continue;
                compressionMethodsList.Add(ReadNullTerminatedString(br));
            }
            
            footer.compressionMethods = compressionMethodsList.ToArray();
        }
        
        return footer;
    }
    
    
    private static Index ReadIndex(BinaryReader br, int version, long position)
    {
        br.BaseStream.Seek(position, SeekOrigin.Begin);
        
        // use legacy function
        if(version < 10) return ReadLegacyIndex(br, version, position);
        
        var index = new Index
        {
            mountPointSize = br.ReadInt32(),
            mountPoint = ReadNullTerminatedString(br),
            entryCount = br.ReadInt32(),
            pathHashSeed = br.ReadUInt64(),
            hasPathHashIndex = Convert.ToBoolean(br.ReadUInt32())
        };

        if (index.hasPathHashIndex)
        {
            index.pathHashIndexOffset = br.ReadInt64();
            index.pathHashIndexSize = br.ReadInt64();
            index.pathHashIndexHash = BitConverter.ToString(br.ReadBytes(20)).Replace("-", string.Empty);
        }

        index.hasFullDirectoryIndex = Convert.ToBoolean(br.ReadUInt32());

        if (index.hasFullDirectoryIndex)
        {
            index.fullDirectoryIndexOffset = br.ReadInt64();
            index.fullDirectoryIndexSize = br.ReadInt64();
            index.fullDirectoryIndexHash = BitConverter.ToString(br.ReadBytes(20)).Replace("-", string.Empty);
        }

        index.encodedEntryInfoSize = br.ReadInt32();
        index.encodedEntryInfo = br.ReadBytes(index.encodedEntryInfoSize);
        index.recordCount = (int) br.ReadUInt32(); // poss unused with ver 10

        return index;
    }

    

    private static Index ReadLegacyIndex(BinaryReader br, int version, long position)
    {
        br.BaseStream.Seek(position, SeekOrigin.Begin);

        var index = new Index();

        index.mountPointSize = br.ReadInt32();
        index.mountPoint = ReadNullTerminatedString(br);
        
        index.recordCount = (int) br.ReadUInt32();
        
        index.indexRecords = new IndexRecord[index.recordCount];

        for (int i = 0; i < index.indexRecords.Length; i++)
        {
            var indexRecord = new IndexRecord
            {
                filenameSize = br.ReadUInt32(),
                filename = ReadNullTerminatedString(br),
                fileMetadata = GetRecord(br, version, br.BaseStream.Position),
            };
            
            // fullpath
            indexRecord.fullpath = $"{index.mountPoint}{indexRecord.filename}";

            //DataRecord
            indexRecord.dataRecord = GetDataRecord(br, version, (long)indexRecord.fileMetadata.offset);

            index.indexRecords[i] = indexRecord;
        }
        
        return index;
    }

    private static Record GetRecord(BinaryReader br, int version, long position)
    {
        // seek to new position
        br.BaseStream.Seek(position, SeekOrigin.Begin);

        /*
         *  version <= 4: offset is absolute to the file
            version 7: offset is relative to the offset field in the corresponding Record
         */
        var compressionBlockOffset = version >= 7 ? position : 0;

        // set up basics for all versions
        var record = new Record()
        {
            offset = br.ReadInt64(),
            size = br.ReadInt64(),
            uncompressedSize = br.ReadInt64(),
            compressionMethod = br.ReadUInt32()
        };

        if (version <= 1) record.timestamp = br.ReadUInt64();

        record.dataHash = BitConverter.ToString(br.ReadBytes(20)).Replace("-", string.Empty); 
            
        if (version >= 3)
        {
            // if compressed
            if (record.compressionMethod != 0)
            {
                record.blockCount = br.ReadUInt32();
                record.compressionBlocks = new CompressionBlock[record.blockCount];


                
                for (int j = 0; j < record.compressionBlocks.Length; j++)
                {
                    
                    record.compressionBlocks[j].startOffset = br.ReadInt64() + compressionBlockOffset;
                    record.compressionBlocks[j].endOffset = br.ReadInt64() + compressionBlockOffset;
                }
            }

            record.isEncrypted = BitConverter.ToBoolean(br.ReadBytes(1));
            record.compressionBlockUncompressedSize = br.ReadUInt32();
        }
                
        // seek to old position
        //br.BaseStream.Seek(oldPosition, SeekOrigin.Begin);
        
        return record;
    }

    private static DataRecord GetDataRecord(BinaryReader br, int version, long position)
    {
        // save old position
        long oldPosition = br.BaseStream.Position;

        // seek to new position
        br.BaseStream.Seek(position, SeekOrigin.Begin);

        var dataRecord = new DataRecord
        {
            fileMetadata = GetRecord(br, version, position),
            dataOffset = br.BaseStream.Position
        };

        // we don't want to read the actual bytes at this point
        // we will save the position (above) for later though
        //dataRecord.fileData = br.ReadBytes((int)dataRecord.fileMetadata.size);
        
        // seek to old position
        br.BaseStream.Seek(oldPosition, SeekOrigin.Begin);
        
        return dataRecord;
    }

    
    private static FullDirectoryIndex ReadFullDirectoryIndex(BinaryReader br, long position)
    {
        var fullDirectoryIndex = new FullDirectoryIndex();

        br.BaseStream.Seek(position, SeekOrigin.Begin);

        fullDirectoryIndex.directoryCount = br.ReadUInt32();
        logger.Debug($"DirectoryCount {fullDirectoryIndex.directoryCount}");

        fullDirectoryIndex.directories = new Directory[fullDirectoryIndex.directoryCount];

        for (int i = 0; i < fullDirectoryIndex.directories.Length; i++)
        {
            var directory = new Directory
            {
                directoryNameSize = br.ReadInt32(),
                directoryName = ReadNullTerminatedString(br),
                fileCount = br.ReadUInt32()
            };

            directory.files = new File[directory.fileCount];

            for (int j = 0; j < directory.files.Length; j++)
            {
                var file = new File
                {
                    filenameSize = br.ReadInt32(),
                    filename = ReadNullTerminatedString(br),
                    encodedEntryInfoOffset = br.ReadUInt32()
                };
                
                directory.files[j] = file;
            }

            fullDirectoryIndex.directories[i] = directory;
        }

        return fullDirectoryIndex;
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
        /*if (version == 8) {
            size += PAK_COMPRESSION_METHOD_COUNT_V8 * PAK_COMPRESSION_METHOD_SIZE;
        } else if (version > 8) {
            size += PAK_COMPRESSION_METHOD_COUNT * PAK_COMPRESSION_METHOD_SIZE;
        }*/
        if (version >= 8) {
            size += PAK_COMPRESSION_METHOD_COUNT * PAK_COMPRESSION_METHOD_SIZE;
        }

        // Version 9 has frozen index flag and version 10 upwards does not
        if (version == 9) {
            size += PAK_BOOL_SIZE;
        }

        return size;
    }
    
    private static string ReadNullTerminatedString(BinaryReader br)
    {
        string str = "";
        char ch;
        while ((int)(ch = br.ReadChar()) != 0)
            str = str + ch;
        return str;
    }
}


