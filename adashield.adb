-- NullSec AdaShield - Cryptographic Protocol Validator
-- Strong typing and contract-based security verification
-- Ada 2012 - Safety-critical systems programming

with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Integer_Text_IO;   use Ada.Integer_Text_IO;
with Ada.Strings.Fixed;     use Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Calendar;          use Ada.Calendar;
with Ada.Containers.Vectors;
with Ada.Containers.Hashed_Maps;
with Ada.Strings.Hash;

procedure AdaShield is

   -- =========================================================================
   -- Type Definitions with Strong Typing
   -- =========================================================================
   
   -- Constrained types for security
   type Protocol_Version is range 1 .. 5;
   type Key_Size is range 128 .. 4096;
   type Risk_Score is delta 0.01 range 0.0 .. 100.0;
   
   -- Enumeration types
   type Protocol_Type is (
      TLS_1_0,
      TLS_1_1,
      TLS_1_2,
      TLS_1_3,
      SSL_3_0,
      SSH_1,
      SSH_2,
      IPSec_IKEv1,
      IPSec_IKEv2
   );
   
   type Cipher_Suite is (
      -- Weak ciphers
      DES_CBC,
      RC4_128,
      DES_EDE3_CBC,
      IDEA_CBC,
      -- Strong ciphers
      AES_128_CBC,
      AES_256_CBC,
      AES_128_GCM,
      AES_256_GCM,
      CHACHA20_POLY1305,
      -- Key exchange
      RSA_1024,
      RSA_2048,
      RSA_4096,
      ECDHE_P256,
      ECDHE_P384,
      ECDHE_X25519
   );
   
   type Severity_Level is (Critical, High, Medium, Low, Info);
   
   type Vulnerability_Type is (
      Weak_Protocol,
      Deprecated_Cipher,
      Small_Key_Size,
      No_Forward_Secrecy,
      Certificate_Issue,
      Misconfiguration,
      Known_CVE
   );
   
   -- =========================================================================
   -- Record Types with Discriminants
   -- =========================================================================
   
   type Certificate_Info is record
      Subject      : Unbounded_String;
      Issuer       : Unbounded_String;
      Valid_From   : Time;
      Valid_Until  : Time;
      Key_Bits     : Key_Size;
      Is_Self_Signed : Boolean;
      Has_OCSP     : Boolean;
   end record;
   
   type Protocol_Config is record
      Protocol     : Protocol_Type;
      Cipher       : Cipher_Suite;
      Key_Exchange : Cipher_Suite;
      Key_Bits     : Key_Size;
      Has_PFS      : Boolean;
   end record;
   
   type Finding is record
      Vuln_Type    : Vulnerability_Type;
      Severity     : Severity_Level;
      Description  : Unbounded_String;
      Remediation  : Unbounded_String;
      MITRE_ID     : Unbounded_String;
      CVE_ID       : Unbounded_String;
      Risk         : Risk_Score;
   end record;
   
   -- =========================================================================
   -- Container Instantiations
   -- =========================================================================
   
   package Finding_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Finding);
   
   package Config_Vectors is new Ada.Containers.Vectors
     (Index_Type   => Natural,
      Element_Type => Protocol_Config);
   
   -- =========================================================================
   -- Subtype with Predicates (Ada 2012)
   -- =========================================================================
   
   subtype Strong_Key_Size is Key_Size
     with Static_Predicate => Strong_Key_Size >= 2048;
   
   subtype Modern_Protocol is Protocol_Type
     with Static_Predicate => Modern_Protocol in TLS_1_2 | TLS_1_3 | SSH_2 | IPSec_IKEv2;
   
   subtype Weak_Cipher is Cipher_Suite
     with Static_Predicate => Weak_Cipher in DES_CBC | RC4_128 | DES_EDE3_CBC | RSA_1024;
   
   -- =========================================================================
   -- Contract-based Programming with Pre/Post Conditions
   -- =========================================================================
   
   function Is_Protocol_Deprecated (Proto : Protocol_Type) return Boolean is
     (Proto in SSL_3_0 | TLS_1_0 | TLS_1_1 | SSH_1 | IPSec_IKEv1)
   with Inline;
   
   function Is_Cipher_Weak (Ciph : Cipher_Suite) return Boolean is
     (Ciph in DES_CBC | RC4_128 | DES_EDE3_CBC | IDEA_CBC | RSA_1024)
   with Inline;
   
   function Supports_PFS (KX : Cipher_Suite) return Boolean is
     (KX in ECDHE_P256 | ECDHE_P384 | ECDHE_X25519)
   with Inline;
   
   function Calculate_Risk (
      Proto : Protocol_Type;
      Ciph  : Cipher_Suite;
      Bits  : Key_Size
   ) return Risk_Score
   with
      Pre  => Bits >= 128,
      Post => Calculate_Risk'Result >= 0.0 and Calculate_Risk'Result <= 100.0;
   
   function Calculate_Risk (
      Proto : Protocol_Type;
      Ciph  : Cipher_Suite;
      Bits  : Key_Size
   ) return Risk_Score is
      Score : Risk_Score := 0.0;
   begin
      -- Protocol scoring
      case Proto is
         when SSL_3_0    => Score := Score + 40.0;
         when TLS_1_0    => Score := Score + 30.0;
         when TLS_1_1    => Score := Score + 20.0;
         when SSH_1      => Score := Score + 35.0;
         when IPSec_IKEv1 => Score := Score + 15.0;
         when others     => Score := Score + 0.0;
      end case;
      
      -- Cipher scoring
      if Is_Cipher_Weak (Ciph) then
         Score := Score + 30.0;
      end if;
      
      -- Key size scoring
      if Bits < 2048 then
         Score := Score + 25.0;
      elsif Bits < 1024 then
         Score := Score + 50.0;
      end if;
      
      -- Cap at 100
      if Score > 100.0 then
         Score := 100.0;
      end if;
      
      return Score;
   end Calculate_Risk;
   
   -- =========================================================================
   -- Validation Functions with Contracts
   -- =========================================================================
   
   procedure Validate_Protocol (
      Config   : Protocol_Config;
      Findings : in out Finding_Vectors.Vector
   )
   with
      Pre => Config.Key_Bits >= 128;
   
   procedure Validate_Protocol (
      Config   : Protocol_Config;
      Findings : in out Finding_Vectors.Vector
   ) is
      F : Finding;
   begin
      -- Check deprecated protocols
      if Is_Protocol_Deprecated (Config.Protocol) then
         F := (
            Vuln_Type   => Weak_Protocol,
            Severity    => High,
            Description => To_Unbounded_String (
               "Deprecated protocol: " & Protocol_Type'Image (Config.Protocol)
            ),
            Remediation => To_Unbounded_String (
               "Upgrade to TLS 1.2 or TLS 1.3"
            ),
            MITRE_ID    => To_Unbounded_String ("T1557"),
            CVE_ID      => To_Unbounded_String (""),
            Risk        => Calculate_Risk (Config.Protocol, Config.Cipher, Config.Key_Bits)
         );
         Findings.Append (F);
      end if;
      
      -- Check weak ciphers
      if Is_Cipher_Weak (Config.Cipher) then
         F := (
            Vuln_Type   => Deprecated_Cipher,
            Severity    => High,
            Description => To_Unbounded_String (
               "Weak cipher suite: " & Cipher_Suite'Image (Config.Cipher)
            ),
            Remediation => To_Unbounded_String (
               "Use AES-256-GCM or ChaCha20-Poly1305"
            ),
            MITRE_ID    => To_Unbounded_String ("T1040"),
            CVE_ID      => To_Unbounded_String (""),
            Risk        => 35.0
         );
         Findings.Append (F);
      end if;
      
      -- Check key size
      if Config.Key_Bits < 2048 then
         F := (
            Vuln_Type   => Small_Key_Size,
            Severity    => Medium,
            Description => To_Unbounded_String (
               "Insufficient key size:" & Key_Size'Image (Config.Key_Bits) & " bits"
            ),
            Remediation => To_Unbounded_String (
               "Use minimum 2048-bit keys, prefer 4096-bit"
            ),
            MITRE_ID    => To_Unbounded_String ("T1588.004"),
            CVE_ID      => To_Unbounded_String (""),
            Risk        => 25.0
         );
         Findings.Append (F);
      end if;
      
      -- Check forward secrecy
      if not Config.Has_PFS then
         F := (
            Vuln_Type   => No_Forward_Secrecy,
            Severity    => Medium,
            Description => To_Unbounded_String (
               "No Perfect Forward Secrecy configured"
            ),
            Remediation => To_Unbounded_String (
               "Enable ECDHE key exchange (P-256, P-384, or X25519)"
            ),
            MITRE_ID    => To_Unbounded_String ("T1557"),
            CVE_ID      => To_Unbounded_String (""),
            Risk        => 20.0
         );
         Findings.Append (F);
      end if;
   end Validate_Protocol;
   
   -- =========================================================================
   -- Output Formatting
   -- =========================================================================
   
   procedure Print_Banner is
   begin
      Put_Line ("");
      Put_Line ("╔══════════════════════════════════════════════════════════════════╗");
      Put_Line ("║         NullSec AdaShield - Cryptographic Protocol Validator     ║");
      Put_Line ("╚══════════════════════════════════════════════════════════════════╝");
      Put_Line ("");
   end Print_Banner;
   
   function Severity_To_String (Sev : Severity_Level) return String is
   begin
      case Sev is
         when Critical => return "[CRITICAL]";
         when High     => return "[HIGH]    ";
         when Medium   => return "[MEDIUM]  ";
         when Low      => return "[LOW]     ";
         when Info     => return "[INFO]    ";
      end case;
   end Severity_To_String;
   
   function Severity_Color (Sev : Severity_Level) return String is
   begin
      case Sev is
         when Critical => return ASCII.ESC & "[91m";
         when High     => return ASCII.ESC & "[93m";
         when Medium   => return ASCII.ESC & "[33m";
         when Low      => return ASCII.ESC & "[94m";
         when Info     => return ASCII.ESC & "[90m";
      end case;
   end Severity_Color;
   
   Reset_Color : constant String := ASCII.ESC & "[0m";
   
   procedure Print_Finding (F : Finding) is
   begin
      Put_Line ("");
      Put (Severity_Color (F.Severity));
      Put_Line ("  " & Severity_To_String (F.Severity) & " " & To_String (F.Description));
      Put_Line (Reset_Color);
      Put_Line ("    Type:        " & Vulnerability_Type'Image (F.Vuln_Type));
      Put ("    Risk Score:  ");
      Put (Integer (F.Risk), Width => 1);
      Put_Line ("/100");
      Put_Line ("    MITRE:       " & To_String (F.MITRE_ID));
      if Length (F.CVE_ID) > 0 then
         Put_Line ("    CVE:         " & To_String (F.CVE_ID));
      end if;
      Put_Line ("    Remediation: " & To_String (F.Remediation));
   end Print_Finding;
   
   procedure Print_Summary (Findings : Finding_Vectors.Vector) is
      Critical_Count : Natural := 0;
      High_Count     : Natural := 0;
      Medium_Count   : Natural := 0;
      Low_Count      : Natural := 0;
      Total_Risk     : Float := 0.0;
   begin
      for F of Findings loop
         case F.Severity is
            when Critical => Critical_Count := Critical_Count + 1;
            when High     => High_Count := High_Count + 1;
            when Medium   => Medium_Count := Medium_Count + 1;
            when Low      => Low_Count := Low_Count + 1;
            when Info     => null;
         end case;
         Total_Risk := Total_Risk + Float (F.Risk);
      end loop;
      
      Put_Line ("");
      Put_Line ("═══════════════════════════════════════════════════════════════════");
      Put_Line ("");
      Put_Line ("  Summary:");
      Put ("    Total Findings:  ");
      Put (Integer (Findings.Length), Width => 1);
      New_Line;
      Put ("    Critical:        ");
      Put (Severity_Color (Critical));
      Put (Critical_Count, Width => 1);
      Put_Line (Reset_Color);
      Put ("    High:            ");
      Put (Severity_Color (High));
      Put (High_Count, Width => 1);
      Put_Line (Reset_Color);
      Put ("    Medium:          ");
      Put (Severity_Color (Medium));
      Put (Medium_Count, Width => 1);
      Put_Line (Reset_Color);
      Put ("    Low:             ");
      Put (Low_Count, Width => 1);
      New_Line;
      Put ("    Aggregate Risk:  ");
      Put (Integer (Total_Risk), Width => 1);
      Put_Line ("/400");
      Put_Line ("");
   end Print_Summary;
   
   -- =========================================================================
   -- Demo Data
   -- =========================================================================
   
   function Get_Demo_Configs return Config_Vectors.Vector is
      Configs : Config_Vectors.Vector;
   begin
      -- Vulnerable TLS 1.0 configuration
      Configs.Append ((
         Protocol     => TLS_1_0,
         Cipher       => DES_EDE3_CBC,
         Key_Exchange => RSA_1024,
         Key_Bits     => 1024,
         Has_PFS      => False
      ));
      
      -- Better but still weak TLS 1.1
      Configs.Append ((
         Protocol     => TLS_1_1,
         Cipher       => AES_128_CBC,
         Key_Exchange => RSA_2048,
         Key_Bits     => 2048,
         Has_PFS      => False
      ));
      
      -- Modern TLS 1.2 with issues
      Configs.Append ((
         Protocol     => TLS_1_2,
         Cipher       => RC4_128,
         Key_Exchange => RSA_2048,
         Key_Bits     => 2048,
         Has_PFS      => False
      ));
      
      -- Secure TLS 1.3
      Configs.Append ((
         Protocol     => TLS_1_3,
         Cipher       => AES_256_GCM,
         Key_Exchange => ECDHE_X25519,
         Key_Bits     => 4096,
         Has_PFS      => True
      ));
      
      -- Legacy SSH
      Configs.Append ((
         Protocol     => SSH_1,
         Cipher       => DES_CBC,
         Key_Exchange => RSA_1024,
         Key_Bits     => 1024,
         Has_PFS      => False
      ));
      
      -- Modern SSH
      Configs.Append ((
         Protocol     => SSH_2,
         Cipher       => CHACHA20_POLY1305,
         Key_Exchange => ECDHE_P384,
         Key_Bits     => 4096,
         Has_PFS      => True
      ));
      
      -- Legacy IPSec
      Configs.Append ((
         Protocol     => IPSec_IKEv1,
         Cipher       => DES_EDE3_CBC,
         Key_Exchange => RSA_2048,
         Key_Bits     => 2048,
         Has_PFS      => False
      ));
      
      return Configs;
   end Get_Demo_Configs;
   
   -- =========================================================================
   -- Main Entry Point
   -- =========================================================================
   
   Configs  : Config_Vectors.Vector;
   Findings : Finding_Vectors.Vector;
   
begin
   Print_Banner;
   Put_Line ("[Demo Mode]");
   Put_Line ("");
   Put_Line ("Scanning cryptographic protocol configurations...");
   
   Configs := Get_Demo_Configs;
   
   Put_Line ("");
   Put ("  Loaded ");
   Put (Integer (Configs.Length), Width => 1);
   Put_Line (" protocol configurations");
   Put_Line ("");
   Put_Line ("Validating protocols against security policies...");
   
   -- Validate each configuration
   for Config of Configs loop
      Put_Line ("");
      Put_Line ("  Checking: " & Protocol_Type'Image (Config.Protocol) &
                " with " & Cipher_Suite'Image (Config.Cipher));
      Validate_Protocol (Config, Findings);
   end loop;
   
   Put_Line ("");
   Put_Line ("");
   Put_Line ("═══════════════════════════════════════════════════════════════════");
   Put_Line ("                         FINDINGS");
   Put_Line ("═══════════════════════════════════════════════════════════════════");
   
   -- Print all findings
   for F of Findings loop
      Print_Finding (F);
   end loop;
   
   Print_Summary (Findings);
   
end AdaShield;
