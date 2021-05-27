unit MainUnit;

{$mode objfpc}{$H+}

interface

uses
 Classes,SysUtils,Forms,Controls,Graphics,Dialogs,ExtCtrls,StdCtrls,Buttons,
 ComCtrls,ZStream,crc,Global,StrUtils,Math;

type
  TDynByteArray = Array of Byte;
type
  TFileDetails = record
    Filename : String;
    LoadAddr,
    ExecAddr,
    Length,
    Offset   : Cardinal;
    Data     : TDynByteArray;
  end;

  { TMainForm }

  TMainForm = class(TForm)
   cb_SaveFiles: TCheckBox;
   cb_SkipAnalysis: TCheckBox;
   Label1: TLabel;
   Label2: TLabel;
   Label3: TLabel;
   Label4: TLabel;
   Label5: TLabel;
   Label6: TLabel;
   lb_chunkID: TLabel;
   lb_chunkLen: TLabel;
   lb_chunkDesc: TLabel;
   lb_chunkUnk: TLabel;
   lb_files: TLabel;
   Report: TMemo;
   FileLoader: TMemo;
   Panel1: TPanel;
   Panel2: TPanel;
   Panel3: TPanel;
   Panel4: TPanel;
   SaveDirDialogue: TSelectDirectoryDialog;
   UEFProgress: TProgressBar;
   procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
   procedure ReadUEFFile(source: String);
   function BlockStatus(status: Byte): String;
   function TargetMachine(machine: Byte): String;
   function GetCRC16(start,length: Cardinal;var buffer: TDynByteArray): Cardinal;
   function GetCRC32(var buffer: TDynByteArray): String;
   function Inflate(source: String): TDynByteArray;
   function GetIEEEFloat(input: Cardinal): Real;
  private

  public
   files: array of TFileDetails; //List of all the files
  end;

var
  MainForm: TMainForm;

implementation

{$R *.lfm}

{ TMainForm }

{-------------------------------------------------------------------------------
Accept dropped files onto the form
-------------------------------------------------------------------------------}
procedure TMainForm.FormDropFiles(Sender:TObject;const FileNames:array of String);
var
  i: Integer;
begin
 //We're just passing each one to the file reader procedure
 for i:=0 to Length(FileNames)-1 do
  ReadUEFFile(FileNames[i]);
end;

{-------------------------------------------------------------------------------
Read in and decode the file
-------------------------------------------------------------------------------}
procedure TMainForm.ReadUEFFile(source: String);
var
 F        : TFileStream;
 buffer   : TDynByteArray;
 i,j      : Integer;
 baud     : Real;
 filenum,
 phase,
 unk,
 pos,
 chunkid,
 chunklen,
 blocklen,
 blocknum,
 ptr,
 headcrc,
 datacrc  : Cardinal;
 ok       : Boolean;
 temp,
 line     : String;
 tone     : Real;
 blockst  : Byte;
const
 uefstring = 'UEF File!';
begin
 //Initialise the variables
 buffer:=nil;
 files:=nil;
 unk:=0;
 SetLength(files,0);
 baud:=1200; //Default baud rate
 phase:=180;
 //Reset the controls
 Report.Clear; //The reading of the file would actually go quicker without these
 FileLoader.Clear; //being updated as it read.
 lb_chunkID.Caption:='';
 lb_chunkLen.Caption:='';
 lb_chunkDesc.Caption:='';
 lb_chunkUnk.Caption:='';
 lb_files.Caption:='';
 //Reset the progress bar and show
 UEFProgress.Position:=0;
 UEFProgress.Visible:=True;
 //Begin the report
 Report.Lines.Add('File: "'+source+'"'); //Put the filename in as the first line
 //Open the file
 buffer:=Inflate(source);
 Report.Lines.Add('Total uncompressed file length: '
                +IntToStr(Length(buffer))+' bytes (0x'
                +IntToHex(Length(buffer),10)+')');
 //Test to make sure it is a UEF file
 ok:=True;
 for i:=1 to Length(uefstring) do
  if buffer[i-1]<>Ord(uefstring[i])then ok:=False;
 //If it is, then begin loading
 if ok then
 begin
  Report.Lines.Add('');
  Report.Lines.Add('File is a UEF file');
  Report.Lines.Add('UEF version: '+IntToStr(buffer[$0A])+'.'+IntToStr(buffer[$0B]));
  Report.Lines.Add('');
  //Starting position is after the magic string
  pos:=$0C;
  //Keep track of which file we are on
  filenum:=0;
  //The last block's status byte
  blockst:=$00;
  Report.Lines.Add('UEF Offset   ID     Length     Details');
  Report.Lines.Add(
  '----------------------------------------------------------------------------------------------');
  //Loop through until we run out of bytes
  while pos<Length(buffer) do
  begin
   //Read in the chunk ID
   chunkid :=buffer[pos]
            +buffer[pos+1]*$100;
   //And the chunk length
   chunklen:=buffer[pos+2]
            +buffer[pos+3]*$100
            +buffer[pos+4]*$10000
            +buffer[pos+5]*$1000000;
   lb_chunkID.Caption:='0x'+IntToHex(chunkid,4);
   lb_chunkLen.Caption:='0x'+IntToHex(chunklen,4);
   lb_chunkDesc.Caption:='';
   line:='0x'+IntToHex(pos,10)+' 0x'+IntToHex(chunkid,4)
                              +' 0x'+IntToHex(chunklen,8);
   //Was the last data block seen the last block of the file?
   if blockst AND$80=$80 then
   begin
    inc(filenum);
    blockst:=0;
   end;
   //Move on after the header
   inc(pos,6);
   //Decode the chunk
   case chunkid of
    $0000 : //Origin Information +++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Origin information';
     temp:='';
     for i:=0 to chunklen-1 do
      if(buffer[pos+i]>31)and(buffer[pos+i]<127)then temp:=temp+chr(buffer[pos+i]);
     line:=line+' Created by '+temp;
    end;
    $0005 : //Target Machine Type ++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Target Machine Type';
     line:=line+' Target Machine is '+TargetMachine(buffer[pos]);
    end;
    $0100 : //Implicit Start/Stop Bit Tape Data Block ++++++++++++++++++++++++++
    begin
     line:=line+' Implicit Data Block';
     lb_chunkDesc.Caption:='Implicit Data Block';
     //Check for sync byte
     if buffer[pos]=$2A then // $2A is the sync byte
     begin
      //Read in the filename
      temp:='';
      i:=1;
      while buffer[pos+i]<>$00 do //terminated by null
      begin
       if(buffer[pos+i]>31)and(buffer[pos+i]<127)then temp:=temp+chr(buffer[pos+i]);
       inc(i);
      end;
      //'i' becomes our pointer now
      inc(i);
      //Sometimes a file has no filename, so give it one
      if temp='' then temp:='?';
      //Create a new entry in our array, if need be
      if filenum=Length(files) then
      begin
       SetLength(files,filenum+1);
       files[filenum].Length  :=0;      //Length counter
       files[filenum].Filename:=temp;   //Filename
       files[filenum].Offset  :=pos-6;  //Where to find it (first block)
       SetLength(files[filenum].Data,0);//Clear the data
       FileLoader.Lines.Add(temp);
      end;
      //Read in the load address
      files[filenum].LoadAddr:=buffer[pos+i]
                              +buffer[pos+i+1]*$100
                              +buffer[pos+i+2]*$10000
                              +buffer[pos+i+3]*$1000000;
      //Read in the execution address
      files[filenum].ExecAddr:=buffer[pos+i+4]
                              +buffer[pos+i+5]*$100
                              +buffer[pos+i+6]*$10000
                              +buffer[pos+i+7]*$1000000;
      //Read in the block number
      blocknum:=buffer[pos+i+8]+buffer[pos+i+9]*$100;
      line:=line+' #'+IntToHex(blocknum,4);
      //Take a note of where we are in the file's data, as we build it up
      ptr:=files[filenum].Length;
      //Get the length of this block
      blocklen:=buffer[pos+i+10]+buffer[pos+i+11]*$100;
      //And add it to the total length
      inc(files[filenum].Length,blocklen);
      //Get the block status
      blockst:=buffer[pos+i+12];
      //Get the CRC16 value for the header
      headcrc:=buffer[pos+i+17]+buffer[pos+i+18]*$100;
      //Check it is valid
      if headcrc=GetCRC16(pos+1,i+16,buffer) then line:=line+' Header OK';
      //Move our chunk pointer onto the data
      inc(i,19);//Points to the data
      //Increase the file's data length to match the total length, so far
      SetLength(files[filenum].Data,files[filenum].Length);
      //And copy in the data in this block
      for j:=0 to blocklen-1 do files[filenum].Data[ptr+j]:=buffer[pos+i+j];
      //Move to after the data
      inc(i,blocklen);
      //So we can read in the data's CRC
      datacrc:=buffer[pos+i]+buffer[pos+i+1]*$100;
      //Check it is valid
      if datacrc=GetCRC16(pos+i-blocklen,blocklen,buffer) then line:=line+' Data OK';
      //Update the 'file loader' display
      FileLoader.Lines[filenum]:=files[filenum].Filename
                           +LeftStr('          ',10-Length(files[filenum].Filename))
                           +' '+IntToHex(blocknum,2);
      //Display the length, as per BBC Micro, if last block
      if blockst AND $80=$80 then
       FileLoader.Lines[filenum]:=PadRight(files[filenum].Filename,10)
                            +' '+IntToHex(blocknum,2)
                            +' '+IntToHex(files[filenum].Length,4)
                            +' '+IntToHex(files[filenum].LoadAddr,8)
                            +' '+IntToHex(files[filenum].ExecAddr,8);
     end
     else line:=line+' (no sync byte)';
    end;
    $0110 : //High Tone ++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='High Tone';
     //Work out the length of the tone
     tone:=(buffer[pos]+buffer[pos+1]*$100)*(1/(baud*2))*8;
     line:=line+' High Tone: '+FloatToStr(tone)+'s';
    end;
    $0111 : //High Tone with dummy byte ++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='High Tone with dummy byte';
     //Work out the length of the tone
     tone:=(buffer[pos]+buffer[pos+1]*$100)*(1/(baud*2))*8;
     line:=line+' High Tone with dummy byte: '+FloatToStr(tone)+'s and '+
           FloatToStr((buffer[pos+2]+buffer[pos+3]*$100)*(1/(baud*2))*8)+'s';
    end;
    $0112 : //Baudwise Gap +++++++++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Baudwise Gap';
     //Work out the length of the gap
     tone:=(buffer[pos]+buffer[pos+1]*$100)*(1/(baud*2))*8;
     line:=line+' Baudwise Gap: '+FloatToStr(tone)+'s';
    end;
    $0113 : //Change of baud rate ++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Change of baud rate';
     //Work out the new baud rate
     baud:=GetIEEEFloat(buffer[pos]
                       +buffer[pos+1]*$100
                       +buffer[pos+2]*$10000
                       +buffer[pos+3]*$1000000);
     line:=line+' Change of baud rate: '+FloatToStr(baud);
    end;
    $0114 : //Security wave ++++++++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Security wave';
     line:=line+' Security wave: '+IntToStr(buffer[pos]
                                           +buffer[pos+1]*$100
                                           +buffer[pos+2]*$10000)
               +' waves ('+chr(buffer[pos+3])+chr(buffer[pos+4])+')';
    end;
    $0115 : //Phase Change +++++++++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Phase Change';
     phase:=buffer[pos]+buffer[pos+1]*$100;
     line:=line+' Phase Change: '+IntToStr(phase);
    end;
    $0116 : //Floating point gap +++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Floating point gap';
     //Work out the length of the gap
     tone:=GetIEEEFloat(buffer[pos]
                       +buffer[pos+1]*$100
                       +buffer[pos+2]*$10000
                       +buffer[pos+3]*$1000000);
     line:=line+' Floating point gap: '+FloatToStr(tone)+'s';
    end;
    else //Unknown chunk +++++++++++++++++++++++++++++++++++++++++++++++++++++++
    begin
     lb_chunkDesc.Caption:='Unknown';
     inc(unk);
    end;
   end;
   if(line<>'')and(not cb_SkipAnalysis.Checked)then Report.Lines.Add(line);
   //Move our offset pointer to the next chunk
   inc(pos,chunklen);
   //Update the progress bar
   UEFProgress.Position:=Round((pos/Length(buffer))*UEFPRogress.Max);
   //Update the 'Unknown chunks' counter
   lb_chunkUnk.Caption:=IntToStr(unk);
   //Update the file counter
   lb_files.Caption:=IntToStr(Length(files));
   //Update the form
   Application.ProcessMessages;
  end;
  //Report back findings
  Report.Lines.Add('Number of unknown chunks: '+IntToStr(unk));
  Report.Lines.Add('Number of files         : '+IntToStr(Length(files)));
  if Length(files)>0 then
  begin
   //Has the user requested to save the files?
   if cb_SaveFiles.Checked then
   begin
    //Set the intial directory to be the same as the current one
    SaveDirDialogue.InitialDir:=ExtractFilePath(source);
    //Open the save dialogue
    if SaveDirDialogue.Execute then
    begin
     //Get the selected directory
     line:=SaveDirDialogue.FileName;
     //Make sure it has a path delimiter at the end
     if line[Length(line)]<>PathDelim then line:=line+PathDelim;
     //So we can tack on our filename
     line:=line+ExtractFilename(source)+'-files'+PathDelim;
     //Create the directory to store the files
     if not FileExists(line) then
     try
      CreateDir(line);
     except
      ShowMessage('Could not create directory');
      cb_SaveFiles.Checked:=False;
     end;
    end
    else //User cancelled the save operation
     cb_SaveFiles.Checked:=False;
   end;
   //Go through them all that we have read, and add to the report
   Report.Lines.Add('');
   Report.Lines.Add('Filename   Length Load Addr  Exec Addr  UEF Offset   CRC32');
   Report.Lines.Add('---------------------------------------------------------------');
   for filenum:=0 to Length(files)-1 do
   begin
    Report.Lines.Add(PadRight(files[filenum].Filename,10)
                  +' 0x'+IntToHex(files[filenum].Length,4)
                  +' 0x'+IntToHex(files[filenum].LoadAddr,8)
                  +' 0x'+IntToHex(files[filenum].ExecAddr,8)
                  +' 0x'+IntToHex(files[filenum].Offset,10)
                  +' 0x'+GetCRC32(files[filenum].Data));
    //If user has specified, then save them
    if cb_SaveFiles.Checked then
    begin
     //Create the filename
     temp:=files[filenum].Filename;
     //Make sure that the filename does not already exist
     if FileExists(line+temp) then
     begin
      //If it does, we'll put a number after it to make it unique
      i:=1;
      while FileExists(line+temp+'('+IntToStr(i)+')') do inc(i);
      //Add the number
      temp:=temp+'('+IntToStr(i)+')';
     end;
     try
      //Open the stream to write the file out
      F:=TFileStream.Create(line+temp,fmCreate);
      //Write out the entire file
      F.Write(files[filenum].Data[0],files[filenum].Length);
      //Then close the stream
      F.Free;
      //Write out the inf file
      F:=TFileStream.Create(line+temp+'.inf',fmCreate);
      WriteLine(F,PadRight(files[filenum].Filename,12)+' '
                 +IntToHex(files[filenum].LoadAddr,8)+' '
                 +IntToHex(files[filenum].ExecAddr,8)+' '
                 +IntToHex(files[filenum].Length,8)+'   '
                 +'CRC32='+GetCRC32(files[filenum].Data));
      F.Free;
     except
      //an error occured
     end;
    end;
   end;
  end;
 end
 else //User tried to open a non-UEF file
  Report.Lines.Add('File is not a UEF file');
 //Reset the progress bar and hide
 UEFProgress.Position:=0;
 UEFProgress.Visible:=False;
end;

{-------------------------------------------------------------------------------
Convert the block status byte into a human readable string
-------------------------------------------------------------------------------}
function TMainForm.BlockStatus(status: Byte): String;
begin
 Result:='';
 if status AND $01=$01 then Result:=Result+'Locked ';
 if status AND $40=$40 then Result:=Result+'Zero length ';
 if status AND $80=$80 then Result:=Result+'Final block';
end;

{-------------------------------------------------------------------------------
Convert the target machine byte into a human readable string
-------------------------------------------------------------------------------}
function TMainForm.TargetMachine(machine: Byte): String;
begin
 Result:='not specified ('+IntToHex(machine,2)+')';
 case machine and 7 of
  0: Result:='BBC Model A';
  1: Result:='Acorn Electron';
  2: Result:='BBC Model B';
  3: Result:='BBC Master';
  4: Result:='Acorn Atom';
 end;
end;

{-------------------------------------------------------------------------------
Calculate the CRC-16 value
-------------------------------------------------------------------------------}
function TMainForm.GetCRC16(start,length: Cardinal;var buffer: TDynByteArray): Cardinal;
var
 addr: Cardinal;
 bit : Byte;
begin
 //Converted from the BBC BASIC version by J.G.Harston
 //mdfs.net
 Result:=0;
 for addr:=start to start+length-1 do
 begin
  Result:=Result XOR $100*buffer[addr]; //EOR with current byte
  for bit:=1 to 8 do                    //Loop through 8 bits
  begin
   Result:=Result shl 1;                //Move CRC up one bit
   if Result AND $10000=$10000 then
    Result:=Result XOR $11021;          //EOR with XMODEM polynomic
  end;                                  //Ensuring CRC remains 16-bit value
 end;
 //Swap the MSB and LSB around
 Result:=((Result mod $100)*$100)+(Result div $100);
end;

{-------------------------------------------------------------------------------
Calculate the CRC-32 value
-------------------------------------------------------------------------------}
function TMainForm.GetCRC32(var buffer: TDynByteArray): String;
var
 CRCValue: longword;
begin
 CRCValue:=crc.crc32(0,nil,0);
 CRCValue:=crc.crc32(0,@buffer[0],Length(buffer));
 Result  :=IntToHex(CRCValue,8);
end;

{-------------------------------------------------------------------------------
Load, and inflate if it is GZipped, a UEF file
-------------------------------------------------------------------------------}
function TMainForm.Inflate(Source: String): TDynByteArray;
 function L_Inflate(Source: String): TDynByteArray;
 var
  GZ     : TGZFileStream;
  chunk  : TDynByteArray;
  cnt,
  i,
  buflen : Integer;
 const
   ChunkSize=4096; //4K chunks
 begin
  //Initialise the variables
  Result:=nil;
  chunk:=nil;
  //Open the stream
  try
   GZ:=TGZFileStream.Create(Source,gzOpenRead);
   //This is our length counter
   buflen:=0;
   //We'll be reading it in chunks
   SetLength(chunk,ChunkSize);
   repeat
    //Read in the next chunk
    cnt:=GZ.Read(chunk[0],ChunkSize);
    //Extend the buffer accordingly
    SetLength(Result,buflen+cnt);
    //Copy the chunk into the buffer
    for i:=0 to cnt-1 do Result[buflen+i]:=chunk[i];
    //Increase the buffer length counter
    inc(buflen,cnt);
    //Until we are done
   until cnt<ChunkSize;
   //Free up the stream
  except
  end;
  GZ.Free;
 end;
var
 F        : TFileStream;
 buffer,
 inflated : TDynByteArray;
 ptr,i,old: Cardinal;
 blockptrs: array of Cardinal;
 fn       : String;
begin
 buffer   :=nil;
 blockptrs:=nil;
 inflated :=nil;
 Result   :=nil;
 //Read in the entire file
 try
  F:=TFileStream.Create(Source,fmOpenRead or fmShareDenyNone);
  SetLength(buffer,F.Size);
  F.Read(buffer[0],F.Size);
 except
 end;
 F.Free;
 //Count how many blocks and make note of their positions
 for ptr:=0 to Length(buffer)-10 do
  if(buffer[ptr]=$1F)and(buffer[ptr+1]=$8B)and(buffer[ptr+2]=$08)then
  begin
   //Make a note of the position
   SetLength(blockptrs,Length(blockptrs)+1);
   blockptrs[Length(blockptrs)-1]:=ptr;
  end;
 //Separate each block, if more than one
 if Length(blockptrs)>1 then
 begin
  //Add the file end to the end of the block pointers
  SetLength(blockptrs,Length(blockptrs)+1);
  blockptrs[Length(blockptrs)-1]:=Length(buffer);
  //Set up the container for the inflated file
  SetLength(Result,0);
  //Get a temporary filename
  fn:=GetTempDir+ExtractFileName(Source);
  //Iterate through the pointers
  for i:=0 to Length(blockptrs)-2 do
  begin
   //Create the temporary file and write the block to it
   try
    F:=TFileStream.Create(fn,fmCreate);
    F.Write(buffer[blockptrs[i]],blockptrs[i+1]-blockptrs[i]);
   except
   end;
   F.Free;
   //Inflate the block
   inflated:=L_Inflate(fn);
   old:=Length(Result); //Previous length of the inflated file
   //Increase the inflated file buffer to accomodate
   SetLength(Result,Length(Result)+Length(inflated));
   //Move the inflated data across
   for ptr:=0 to Length(inflated)-1 do Result[old+ptr]:=inflated[ptr];
  end;
  //Delete the temporary file
  if FileExists(fn) then DeleteFile(fn);
 end;
 //If just the one block, then don't bother splitting
 if Length(blockptrs)=1 then Result:=L_Inflate(Source);
 //If there are no blocks, then just return the entire file
 if Length(blockptrs)=0 then Result:=buffer;
end;

{-------------------------------------------------------------------------------
Calculates an IEEE flost from 32 bit number
-------------------------------------------------------------------------------}
function TMainForm.GetIEEEFloat(input: Cardinal): Real;
var
 f0,f1,f2,f3 : Byte;
 m,e         : Cardinal;
begin
 Result:=0;
 f3:=(input shr 24)mod$100;
 f2:=(input shr 16)mod$100;
 f1:=(input shr  8)mod$100;
 f0:= input        mod$100;
 m:=f0 or (f1 shl 8) or (((f2 and$7F)or$80)shl 16);
 Result:=ldexp(m,-23);
 e:=((f2 and$80)shr 7)or((f3 and$7F)shl 1);
 e:=e-127;//dec(e,127);
 Result:=ldexp(Result,e);
 if (f3 and$80)=$80 then Result:=-Result;
end;

end.
