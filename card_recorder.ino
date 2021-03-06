#include <Wire.h>
#include <Adafruit_PN532.h>

// The default Mifare Classic key

uint8_t KEY_DEFAULT_KEYAB[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

uint8_t KEY_OMO_KEYAB[6] = {0x21, 0x48, 0x55, 0x49, 0x3B, 0x2B};

uint8_t KEY_DEFAULT_KEY1[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
uint8_t KEY_DEFAULT_KEY2[6] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5};
uint8_t KEY_DEFAULT_KEY3[6] = {0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD};
uint8_t KEY_DEFAULT_KEY4[6] = {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a};
uint8_t KEY_DEFAULT_KEY5[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
uint8_t KEY_DEFAULT_KEY6[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t KEY_DEFAULT_KEY7[6] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7};
uint8_t KEY_DEFAULT_KEY8[6] = {0xb2, 0x10, 0xb2, 0x10, 0xb2, 0x10};

uint8_t *KEY_ARR[9] = {KEY_DEFAULT_KEY1, KEY_DEFAULT_KEY2, KEY_DEFAULT_KEY3, KEY_DEFAULT_KEY4, KEY_DEFAULT_KEY5, KEY_DEFAULT_KEY6, KEY_DEFAULT_KEY7, KEY_DEFAULT_KEY8, KEY_OMO_KEYAB};

static const uint8_t KEY_DEFAULT_KEYAB_WRITE[16] = {0x21, 0x48, 0x55, 0x49, 0x3B, 0x2B, 0xFF, 0x07, 0x80, 0x69, 0x21, 0x48, 0x55, 0x49, 0x3B, 0x2B};


void getRandomUserId(void);
void setUserId(String userId);
void setUserId(char *userId);


uint8_t UserID[48] =  {0}; // 8-4-4-4-12
uint8_t ndefprefix = NDEF_URIPREFIX_NONE;

// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
#define PN532_IRQ   (2)
#define PN532_RESET (3)  // Not connected by default on the NFC Shield

// Or use this line for a breakout or shield with an I2C connection:
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);

void setup(void) {
  pinMode(13, OUTPUT);
  pinMode(12, OUTPUT);
  
  // has to be fast to dump the entire memory contents!
  Serial.begin(115200);
  Serial.println("Looking for PN532...");

  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata>>24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata>>16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata>>8) & 0xFF, DEC);

  // configure board to read RFID tags
  nfc.SAMConfig();

  Serial.println("Waiting for an ISO14443A Card ...");
}


void loop(void) {

  // #########################################################################################################################
  //getRandomUserId();
  //setUserId("df298eec-6cd1-4418-ae63-e796828c17ab");
  // #########################################################################################################################
  Serial.print("Enter the UserId: ");
  String inString;
  while (Serial.available() == 0) {}

  while (Serial.available() > 0) {
    int inChar = Serial.read();
      inString += (char)inChar; 
      Serial.print(inChar);
    if (inChar == '\n') {
      Serial.println();
      Serial.print("UserId: ");
      Serial.println(inString);
      //Serial.print("size of str: ");Serial.println(inString.length());
      if(inString.length() == 37)
      {
        setUserId(inString);
      }
      else if(inString.length() == 1)
      {
        
      }
      else
      {
        Serial.println("Invalid userId!");
      }
      inString = ""; 
    }
  }
  // #########################################################################################################################


  
  uint8_t success;                          // Flag to check if there was an error with the PN532
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  uint8_t currentblock;                     // Counter to keep track of which block we're on
  bool authenticated = false;               // Flag to indicate if the sector is authenticated
  uint8_t data[16];                         // Array to store block data during reads

  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);

  if (success) {
    // Display some basic information about the card
    /*Serial.println("Found an ISO14443A card");
    Serial.print("  UID Length: ");Serial.print(uidLength, DEC);Serial.println(" bytes");
    Serial.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    Serial.println("");*/

    if (uidLength == 4)
    {
      // We probably have a Mifare Classic card ...
      //Serial.println("Seems to be a Mifare Classic card (4 byte UID)");

      // Now we try to go through all 16 sectors (each having 4 blocks)
      // authenticating each sector, and then dumping the blocks
      for (currentblock = 4; currentblock < 8; currentblock++)
      {
        // Check if this is a new block so that we can reauthenticate
        if (nfc.mifareclassic_IsFirstBlock(currentblock)) authenticated = false;

        // If the sector hasn't been authenticated, do so first
        if (!authenticated)
        {

            // Starting of a new sector ... try to to authenticate
            Serial.print("------------------------Sector ");Serial.print(currentblock/4, DEC);Serial.println("-------------------------");
            if (currentblock == 0)
            {
                // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
                // or 0xA0 0xA1 0xA2 0xA3 0xA4 0xA5 for NDEF formatted cards using key a,
                // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
                success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, KEY_DEFAULT_KEYAB);

                if(!success)
                {
                  for(int i=0; i<8; i++)
                  {
                    nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
                    success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, KEY_ARR[i]);
                    
                    if(success)
                    {
                      break;
                    }
                  }
                }
            }
            else
            {
                // This will be 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF for Mifare Classic (non-NDEF!)
                // or 0xD3 0xF7 0xD3 0xF7 0xD3 0xF7 for NDEF formatted cards using key a,
                // but keyb should be the same for both (0xFF 0xFF 0xFF 0xFF 0xFF 0xFF)
                success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, KEY_DEFAULT_KEYAB);

                if(!success)
                {
                  for(int i=0; i<9; i++)
                  {
                    nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
                    success = nfc.mifareclassic_AuthenticateBlock (uid, uidLength, currentblock, 1, KEY_ARR[i]);
                    
                    if(success)
                    {
                      break;
                    }
                  }
                }
            }
            
            if (success)
            {
              authenticated = true;              
            }
            else
            {
                
              Serial.println("Authentication error");
            }
          
        }
        
        // If we're still not authenticated just skip the block
        if (!authenticated)
        {
          // если не подходит пароль
          Serial.print("Block ");Serial.print(currentblock, DEC);Serial.println(" unable to authenticate");
        }
        else
        {
          

          
          if(currentblock == 4)
          {
            success = nfc.mifareclassic_WriteDataBlock(currentblock, &UserID[0]);
          }
          else if(currentblock == 5)
          {
            success = nfc.mifareclassic_WriteDataBlock(currentblock, &UserID[16]);
          }
          else if(currentblock == 6)
          {
            success = nfc.mifareclassic_WriteDataBlock(currentblock, &UserID[32]);
          }
          else if(currentblock == 7)
          {
            success = nfc.mifareclassic_WriteDataBlock(currentblock, &KEY_DEFAULT_KEYAB_WRITE[0]);
          }

          if (success)
          {
            // прошивка кард айди прошла успешно
            //Serial.println("NDEF URI Record written to sector 1");
          }
          else
          {
          
            Serial.println("NDEF Record creation failed! :(");
          }

          // Authenticated ... we should be able to read the block now
          // Dump the data into the 'data' array
          success = nfc.mifareclassic_ReadDataBlock(currentblock, data);

          if (success)
          {
            // Read successful
            Serial.print("Block ");Serial.print(currentblock, DEC);
            if (currentblock < 10)
            {
              Serial.print("  ");
            }
            else
            {
              Serial.print(" ");
            }

            if(currentblock != 7)
            {
              // Dump the raw data
              nfc.PrintHexChar(data, 16);
            }

            if(currentblock == 7)
            {
              for(int i=0; i<4;i++)
              {
                digitalWrite(12, HIGH); 
                delay(100);
                digitalWrite(12, LOW); 
                delay(100);
              }
            }
          }
          else
          {
            // Oops ... something happened
            Serial.print("Block ");Serial.print(currentblock, DEC);
            Serial.println(" unable to read this block");

            if(currentblock == 7)
            {
              for(int i=0; i<4;i++)
              {
                digitalWrite(13, HIGH); 
                delay(100);
                digitalWrite(13, LOW); 
                delay(100);
              }
            }
          }
        }        
      }
    }
    else
    {
      Serial.println("Ooops ... this doesn't seem to be a Mifare Classic card!");
    }
  }
  // Wait a bit before trying again
  Serial.println("\n\nSend a character to run the mem dumper again!");
  //Serial.flush();
  //while (!Serial.available());
  while (Serial.available()) {
  Serial.read();
  }
  Serial.flush();
}

























































// "df1ff3ef-5ddd-4145-8e7d-5585f746c0c8"; // 8-4-4-4-12
void getRandomUserId(void)
{
  for(int i=0; i<48; i++)
  {
    UserID[i] = 0;
  }
  
  char symbols[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
  
  for(int i=0; i<36; i++)
  {
    UserID[i] = symbols[random(0, 16)];
  }

  UserID[8] = '-';
  UserID[13] = '-';
  UserID[18] = '-';
  UserID[23] = '-';
}

void setUserId(String userId)
{
  for(int i=0; i<48; i++)
  {
    UserID[i] = 0;
  }
  
  for(int i=0; i<36; i++)
  {
    UserID[i] = userId[i];
    //Serial.print(UserID[i]);
  }
}

char tempUserId[36] = {0};

void setUserId(char *userId)
{
  for(int i=0; i<48; i++)
  {
    UserID[i] = 0;
  }
  
  for(int i=0; i<36; i++)
  {
    UserID[i] = userId[i];
  }
}
