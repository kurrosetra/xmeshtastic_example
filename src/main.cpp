#include <Arduino.h>
#include <Crypto.h>
#include <ChaCha.h>
#include <rBase64.h>
#include "esp_random.h"

const int ledPin = 8; // On-board LED pin for ESP32-C3
const int rx1Pin = 3; // UART1 RX pin
const int tx1Pin = 4; // UART1 TX pin

const uint8_t key[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};
uint8_t nonce[13] = {0}; // to be filled with random bytes each send session
ChaCha chacha;           // ChaCha20 cipher object

void generate_random_string(char *output, const size_t length);
String chacha20_encrypt(const String &plaintext, const uint8_t *key, const uint8_t *nonce);
String chacha20_decrypt(const String &b64ciphertext, const uint8_t *key, const uint8_t *nonce);

void setup()
{
    pinMode(ledPin, OUTPUT);
    digitalWrite(ledPin, LOW); // Turn on LED
    Serial.begin(115200);
    pinMode(rx1Pin, INPUT_PULLUP);
    Serial1.begin(38400, SERIAL_8N1, rx1Pin, tx1Pin);

    Serial.println("ESP32-MESH-HT");
    delay(1000);
}

void loop()
{
    static const int MESH_PAYLOAD_OFFSET = 5;
    static String payload = "";

    if (Serial.available() > 0)
    {
        String inData = Serial.readStringUntil('\n');
        if (inData.startsWith("MESH:"))
        {
            int payload_offset = MESH_PAYLOAD_OFFSET;
            // find id if any
            int id_index = inData.indexOf(',', payload_offset);
            String id_str = "";
            bool valid_id_found = false;
            if (id_index > payload_offset && id_index <= MESH_PAYLOAD_OFFSET + payload_offset) // from 0 to 65.535 max
            {
                id_str = inData.substring(payload_offset, id_index);
                if (id_str.length() > 0 && id_str.toInt() == 0)
                {
                    Serial.println(id_str);
                    Serial.println("Invalid Target ID, must be numeric and non-zero");
                    Serial.println("it's must be a part of message");
                }
                else
                {
                    String _id = String(id_str.toInt());
                    if (_id.length() != id_str.length())
                    {
                        Serial.printf("Target ID: %s != %d\n", id_str.c_str(), id_str.toInt());
                        Serial.println("it's must be a part of message");
                    }
                    else
                    {
                        Serial.printf("Target ID: %s=%d\n", id_str.c_str(), id_str.toInt());
                        payload_offset = id_index + 1;
                        valid_id_found = true;
                    }
                }
            }

            String meshData = inData.substring(payload_offset); // Extract data after "MESH:"
            Serial.printf("string to send: %s\n", meshData.c_str());
            generate_random_string((char *)nonce, 12); // Generate random nonce
            Serial.printf("Generated Nonce: %s\n", nonce);
            String encryptedData = chacha20_encrypt(meshData, key, nonce);
            if (encryptedData.length() < 128)
            {
                String dataToSend = "";
                if (valid_id_found)
                    dataToSend = "SMS:" + id_str + String(",") + String((char *)nonce) + encryptedData + "\n";
                else
                    dataToSend = "SMS:" + String((char *)nonce) + encryptedData + "\n";
                Serial1.print(dataToSend);
                Serial.printf("U1TX[%dB]: %s\n", dataToSend.length(), dataToSend.c_str());

                // test decryption locally
                String dRaw = dataToSend.substring(4 + (valid_id_found ? id_str.length() + 1 : 0)); // remove "SMS:" & ID if any
                String nonceStr = dRaw.substring(0, 12);
                String b64ciphertext = dRaw.substring(12); // Extract Base64 ciphertext
                Serial.printf("U1Rx[%dB]: nonce[%dB]=%s, cText[%dB]=%s\n", dataToSend.length(), nonceStr.length(), nonceStr.c_str(),
                              b64ciphertext.length(), b64ciphertext.c_str());
                memcpy(nonce, nonceStr.c_str(), 12);                                // Copy nonce
                String decryptedData = chacha20_decrypt(b64ciphertext, key, nonce); // Decrypt data
                Serial.println("Decrypted Data: " + decryptedData);
            }
            else
            {
                Serial.println("Error: Encrypted data too long to send via SMS");
            }
        }
        else
            Serial1.print(inData); // pass through other data
    }

    if (Serial1.available() > 0)
    {
        String inData = Serial1.readStringUntil('\n');
        if (inData.startsWith("SMS<"))
        {
            if (payload.length() > 0)
            {
                String nonceStr = payload.substring(0, 12);   // Extract nonce
                String b64ciphertext = payload.substring(12); // Extract Base64 ciphertext
                payload = "";                                 // clear payload
                Serial.printf("U1Rx[%dB]: nonce[%dB]=%s, cText[%dB]=%s\n", inData.length(), nonceStr.length(), nonceStr.c_str(),
                              b64ciphertext.length(), b64ciphertext.c_str());
                memcpy(nonce, nonceStr.c_str(), 12);                                // Copy nonce
                String decryptedData = chacha20_decrypt(b64ciphertext, key, nonce); // Decrypt data
                Serial.println("Decrypted Data: " + decryptedData);
            }
            payload = ""; // clear payload
        }
        else if (inData.startsWith("payload<"))
        {
            payload = inData.substring(8); // initialize payload
            Serial.printf("payload size: %dB\n", payload.length());
            Serial.println("payload data: " + payload);
        }
        else
            Serial.println(inData); // pass through other data

        digitalWrite(ledPin, !digitalRead(ledPin)); // Toggle LED
    }
}

void generate_random_string(char *output, const size_t length)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    size_t charset_size = sizeof(charset);

    memset(output, 0, sizeof(output));
    for (size_t i = 0; i < length; i++)
    {
        uint32_t rand_val = esp_random();                   // hardware RNG
        output[i] = charset[rand_val % (charset_size - 1)]; // -1 to exclude null terminator
    }
}

String chacha20_encrypt(const String &plaintext, const uint8_t *key, const uint8_t *nonce)
{
    size_t len = plaintext.length();
    uint8_t ciphertext[256]; // Ensure this is large enough for your plaintext

    // Set key and nonce
    chacha.setKey(key, 32);
    chacha.setIV(nonce, 12);

    // Encrypt
    chacha.encrypt(ciphertext, (const uint8_t *)plaintext.c_str(), len);

    if (rbase64_enc_len(strlen((char *)ciphertext)) <= RBASE64_ENC_SIZECALC(256))
    {
        char b64output[256]; // Ensure this is large enough for Base64 output
        size_t b64len = rbase64_encode(b64output, (char *)ciphertext, len);
        b64output[b64len] = '\0'; // Null-terminate string

        return String(b64output);
    }

    return ""; // Return empty string on failure
}

String chacha20_decrypt(const String &b64ciphertext, const uint8_t *key, const uint8_t *nonce)
{
    size_t decodedLen = rbase64_dec_len((char *)b64ciphertext.c_str(), b64ciphertext.length());
    uint8_t decodedCiphertext[256]; // Ensure this is large enough for decoded ciphertext

    if (decodedLen <= 256)
    {
        rbase64_decode((char *)decodedCiphertext, (char *)b64ciphertext.c_str(), b64ciphertext.length());

        uint8_t decrypted[256]; // Ensure this is large enough for decrypted plaintext
        // Set key and nonce
        chacha.setKey(key, 32);
        chacha.setIV(nonce, 12);

        // Decrypt
        chacha.decrypt(decrypted, decodedCiphertext, decodedLen);
        decrypted[decodedLen - 1] = '\0'; // Null-terminate string

        return String((char *)decrypted);
    }

    return ""; // Return empty string on failure
}
