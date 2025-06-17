
import DStorage from '../abis/DStorage.json';
import React, { Component } from 'react';
import './App.css';
import Web3 from 'web3';
import {convertBytes} from './helpers'
import './App.css';
import CryptoJS from "crypto-js";
import logo from './blockimage.png';


class App extends Component {

  async componentDidMount() {
    await this.loadWeb3();
    await this.loadBlockchainData();  // Ensures contract is loaded

    // Load audit logs only if the user is an Admin and the contract is loaded
    if (this.state.userRole === "Admin" && this.state.contract) {
        console.log("📜 Loading audit logs...");
        await this.loadAuditLogs();
    }

    // Handle account changes dynamically
    window.ethereum.on("accountsChanged", async (accounts) => {
        if (accounts.length > 0) {
            console.log("🔄 Account changed:", accounts[0]);
            this.setState({ account: accounts[0] }, async () => {
                await this.loadBlockchainData();  // Reload role & permissions

                if (this.state.userRole === "Admin" && this.state.contract) {
                    console.log("📜 Reloading audit logs...");
                    await this.loadAuditLogs();
                }
            });
        }
    });
}

  constructor(props) {
    super(props);
    this.state = {
      memeHash: '',
      buffer: null,
      account: '',
      dstorage: null,
      userRole: null,
      auditSearchQuery: "",
      files: [],
      auditLogs: [],
      selectedFile: null, 
      filesCount: 0
    };
    this.getRole = this.getRole.bind(this); // Bind the function to 'this'
  }

  async loadWeb3() {
    if (window.ethereum) {
      window.web3 = new Web3(window.ethereum);
      await window.ethereum.enable();
    } else if (window.web3) {
      window.web3 = new Web3(window.web3.currentProvider);
    } else {
      window.alert('Non-Ethereum browser detected. You should consider trying MetaMask!');
    }
  }

  getRole() {
    console.log("🔍 User Role:", this.state.userRole);
}

async loadBlockchainData() {
  try {
      if (!window.ethereum) {
          console.error("❌ MetaMask is not installed!");
          alert("Please install MetaMask.");
          return;
      }

      const web3 = new Web3(window.ethereum);
      await window.ethereum.request({ method: "eth_requestAccounts" });

      const accounts = await web3.eth.getAccounts();
      if (accounts.length === 0) {
          console.error("❌ No accounts found. Please connect MetaMask.");
          alert("No accounts detected. Please log in to MetaMask.");
          return;
      }

      console.log("🔹 Accounts:", accounts);
      this.setState({ account: accounts[0] });

      const networkId = await web3.eth.net.getId();
      const networkData = DStorage.networks[networkId];

      if (!networkData) {
          console.error("❌ DStorage contract not deployed to detected network.");
          alert("DStorage contract not deployed to detected network.");
          return;
      }

      const dstorage = new web3.eth.Contract(DStorage.abi, networkData.address);

      if (!dstorage) {
          console.error("❌ Smart contract failed to load!");
          return;
      }

      console.log("✅ Contract Loaded:", dstorage);
      this.setState({ dstorage, contract: dstorage });

      const fileCount = await dstorage.methods.fileCount().call();
      this.setState({ filesCount: fileCount });

      let files = [];
      for (let i = 1; i <= fileCount; i++) {
          const file = await dstorage.methods.files(i).call();
          if (file.fileHash) {
              files.push(file);
          }
      }
      this.setState({ files });

      const userRole = await dstorage.methods.getRole(accounts[0]).call();
      console.log("🔍 Retrieved Role:", userRole || "No Role Found");

      const isAuthorized = userRole === "Admin";

      this.setState({
          userRole: userRole || "Normal User",
          isAuthorized
      });

      console.log("👤 User Role:", userRole);
      console.log("🔓 Authorized:", isAuthorized);

      if (isAuthorized) {
          await this.loadAuditLogs();  // Only Admin can load audit logs
      }

  } catch (error) {
      console.error("❌ Error loading blockchain data:", error);
  }
}

  // 🔒 Check if user is authorized before performing actions
  checkAuthorization(action) {
    if (!this.state.isAuthorized) {
      alert(`❌ Unauthorized: You do not have permission to ${action}.`);
      return false;
    }
    return true;
  }
   
// 🔥 Fetch Audit Logs
  async loadAuditLogs() {
  if (!this.state.contract || !this.state.account) {
      console.error("⚠️ Contract or account not loaded!");
      return;
  }

  try {
      console.log("📜 Fetching audit logs...");

      const logs = await this.state.contract.methods.getAuditLogs().call({
          from: this.state.account // ✅ Required for `onlyAdmin`
      });

      let auditLogs = [];
      for (let i = 0; i < logs[0].length; i++) {
        auditLogs.push({
          timestamp: new Date(parseInt(logs[0][i]) * 1000).toLocaleString(), // convert to readable format
          user: logs[1][i],
          userRole: logs[2][i],
          action: logs[3][i],
          fileName: logs[4][i],
          fileHash: logs[5][i]
      });
      }

      console.log("📜 Retrieved logs:", auditLogs);
      this.setState({ auditLogs });

  } catch (error) {
      console.error("❌ Error fetching audit logs:", error);
  }
}

  captureFile = (event) => {
    event.preventDefault();
    const file = event.target.files[0];

    if (!file) {
        console.log("❌ No file selected!");
        return;
    }

    console.log(`📂 File Selected: ${file.name}`);

    const reader = new FileReader();
    reader.readAsArrayBuffer(file); 

    reader.onloadend = async () => {
        console.log("📖 Reading file as ArrayBuffer...");

        const fileBuffer = new Uint8Array(reader.result);
        console.log("📜 File Buffer Created:", fileBuffer);

        // 🔍 Compute SHA-256 hash for integrity check
        const hashBuffer = await crypto.subtle.digest("SHA-256", fileBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const fileHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        console.log("🛡️ Computed File Hash:", fileHash);
        // AES  key
        const secretKey = "MySecretKey123";                                              //////   KEY FOR ENCRYPTION & DECRYPTION {CHANGE IFF U WANT}

        let binaryString = "";
        const chunkSize = 1024;
        for (let i = 0; i < fileBuffer.length; i += chunkSize) {
            binaryString += String.fromCharCode(...fileBuffer.slice(i, i + chunkSize));
        }
        // Doing Encryption .......
        const base64Data = btoa(binaryString);
        const encryptedData = CryptoJS.AES.encrypt(base64Data, secretKey).toString();
        console.log("🔒 Encrypted File Data:", encryptedData.substring(0, 50) + "...");

        this.setState({
            buffer: encryptedData,
            fileName: file.name,
            originalHash: fileHash  // Save original hash in state
        }, () => {
            console.log("✅ State Updated with Encrypted File and Hash!");
        });
    };

    reader.onerror = (error) => {
        console.error("❌ File Read Error:", error);
    };
};

  handleFileChange = (event) => {
    const file = event.target.files[0]; // Get the first selected file
    if (file) {
      this.setState({ selectedFile: file });
    }
  };

  handleUpload = () => {
    if (!this.state.selectedFile) {
      alert("Please select a file first!");
      return;
    }

    // Your existing upload logic here
    console.log("Uploading:", this.state.selectedFile.name);
  };

  onSubmit = async (event) => {
    event.preventDefault();

    if (!this.state.buffer || !this.state.originalHash) {
      alert("❌ Please select a file before submitting!");
      return;
    }

    if (!this.checkAuthorization("upload files")) return;

    try {
      console.log("🚀 Uploading encrypted file to Pinata...");

      const formData = new FormData();
      const blob = new Blob([this.state.buffer], { type: "text/plain" });
      formData.append("file", blob, this.state.fileName);

      const response = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
        method: "POST",
        headers: {
          authorization: `Bearer {YOUR_PINATA_BEARER_KEY}`,                                   /// INSERT PINATA BEARER KEY {IPFS}
        }, 
        body: formData
      });

      const result = await response.json();
      if (result.IpfsHash) {
        console.log("✅ File uploaded to IPFS:", result);

        const { dstorage, account, fileName, originalHash } = this.state;
        const fileHash = result.IpfsHash;
        const fileSize = result.PinSize;
        const fileType = result.MimeType || "unknown";
        const fileDescription = "Encrypted Log File";

        console.log("📜 Storing encrypted file and hash on Ethereum...");
        await dstorage.methods.uploadFile(fileHash, fileSize, fileType, fileName, fileDescription, "0x" + originalHash)
          .send({ from: account });

        console.log("✅ File and hash stored on Ethereum blockchain!");
        alert("Encrypted file uploaded successfully!");

        this.loadBlockchainData();
      } else {
        console.error("❌ Upload failed:", result);
      }
    } catch (error) {
      console.error("❌ IPFS Upload Error:", error);
    }
  };

deleteFile = async (fileId) => {
  if (!this.checkAuthorization("delete files")) return;

  // 🔒 Extra verification: Ask for secret key before proceeding (for admin only)
  const secretKey = prompt("🔐 Enter the admin secret key to confirm deletion:");
  if (secretKey !== "CompleteDeletion") {                                                 ///   CONFORM DELETION KEY {CHANGE IFF U WANT}
    alert("🚫 Invalid secret key. File deletion cancelled.");
    return;
  }

  try {
    console.log("🗑️ Deleting file:", fileId);
    await this.state.dstorage.methods.deleteFile(fileId).send({ from: this.state.account });
    alert("✅ File deleted successfully!");
    this.loadBlockchainData();
  } catch (error) {
    console.error("❌ Error deleting file:", error);

    if (error.message.includes("Access Denied: Only uploader or Admin can delete")) {
      alert("🚫 You are not authorized to delete this file. This action has been logged.");
    } else {
      alert("❌ An error occurred while trying to delete the file.");
    }
  }
};


  promptForKeyAndDownload = async (fileHash, fileName, fileId) => {
    try {
      console.log("🔍 Fetching stored hash from blockchain...");
      
      const storedHash = await this.fetchStoredIntegrityHash(fileId);
      if (!storedHash) {
        console.error("❌ No integrity hash found on the blockchain!");
        return;
      }

      console.log("📜 Stored Hash:", storedHash);

      const userKey = prompt("Enter decryption key:");
      if (!userKey) return;

      await this.downloadAndDecrypt(fileId, fileHash, fileName, userKey, storedHash);
    } catch (error) {
      console.error("❌ Error in promptForKeyAndDownload:", error);
    }
  };

  // ✅ Fetch the stored hash from blockchain
  fetchStoredIntegrityHash = async (fileId) => {
    try {
      const storedHash = await this.state.dstorage.methods.getFileIntegrityHash(fileId).call();
      console.log("📜 Retrieved Hash from Blockchain:", storedHash);
      return storedHash;
    } catch (error) {
      console.error("❌ Error fetching integrity hash:", error);
      return null;
    }
  };

  
  // ✅ Fetch audit logs with correct mapping
  fetchAuditLogs = async (contract, account) => {
  const result = await contract.methods.getAuditLogs().call({ from: account });

  const logs = result[0].map((_, i) => ({
    timestamp: result[0][i],
    user: result[1][i],
    userRole: result[2][i] ||'Normal User' ,
    action: result[3][i],
    fileName: result[4][i],
    fileHash: result[5][i]
  }));

  return logs;
  };

// ✅ Download audit logs as CSV with userRole and readable timestamp
  downloadAuditLogsCSV = (logs) => {
  const headers = ['Timestamp', 'User Address', 'User Role', 'Action', 'File Name', 'File Hash'];

  const rows = logs.map(log => [
    new Date(log.timestamp * 1000).toLocaleString(), // readable timestamp
    log.user,
    log.userRole,
    log.action,
    log.fileName,
    log.fileHash
  ]);

  const csvContent = [headers, ...rows]
    .map(row => row.map(field => `"${field}"`).join(','))
    .join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.setAttribute('download', 'audit-logs.csv');
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
   };

// Inside a React class component
  downloadAndDecrypt = async (fileId, fileHash, fileName, userKey, storedHash) => {
  try {
    console.log("⬇️ Downloading encrypted file...");

    const response = await fetch(`https://gateway.pinata.cloud/ipfs/${fileHash}`);
    const encryptedText = await response.text();

    console.log("🔓 Attempting decryption...");
    const decryptedBytes = CryptoJS.AES.decrypt(encryptedText, userKey);
    const decryptedBase64 = decryptedBytes.toString(CryptoJS.enc.Utf8);

    if (!decryptedBase64) {
      alert("❌ Decryption failed! Incorrect key or corrupted file.");
      return;
    }

    console.log("✅ Decryption successful, converting Base64 back to binary...");

    // Convert Base64 back to binary
    const binaryString = atob(decryptedBase64);
    const byteArray = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      byteArray[i] = binaryString.charCodeAt(i);
    }

    // 🔍 Compute SHA-256 hash for integrity verification
    const hashBuffer = await crypto.subtle.digest("SHA-256", byteArray);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const computedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Normalize stored hash (remove "0x" if present)
    const normalizedStoredHash = storedHash.startsWith("0x") ? storedHash.slice(2) : storedHash;
    const normalizedComputedHash = computedHash.toLowerCase();

    console.log("🛡️ Computed Hash:", normalizedComputedHash);
    console.log("📜 Stored Hash:", normalizedStoredHash);

    // ✅ Compare hashes
    if (normalizedComputedHash !== normalizedStoredHash) {
      alert(`⚠️ Integrity Check Failed!\nStored Hash: ${normalizedStoredHash}\nComputed Hash: ${normalizedComputedHash}\n\nThe file has been modified or tampered with.`);
      console.error("❌ File integrity compromised!");
      return;
    }

    console.log("✅ Integrity check passed! File is original.");
    alert(`✅ Integrity Check Passed!\nStored Hash: ${normalizedStoredHash}\nComputed Hash: ${normalizedComputedHash}\n\nThe file is authentic and has not been modified.`);

    // 1️⃣ Create and trigger file download
    const blob = new Blob([byteArray], { type: "application/octet-stream" });
    const blobUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.setAttribute("download", fileName);
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();

    // Cleanup
    setTimeout(() => {
      URL.revokeObjectURL(blobUrl);
      link.remove();
    }, 100);

    console.log("✅ File decrypted and downloaded!");
    alert("✅ File decrypted and saved successfully!");

    // 2️⃣ AFTER download, record the download action on the blockchain
    try {
      const { dstorage, account } = this.state;
      await dstorage.methods.recordDownload(fileId).send({ from: account });
      console.log("📜 Download action logged on blockchain.");
    } catch (logError) {
      console.error("⚠️ Failed to log download on blockchain:", logError);
    }

  } catch (error) {
    console.error("❌ Error downloading or decrypting file:", error);
    alert("❌ An error occurred while decrypting the file.");
  }
  };

render() {
  return (
    <div>
      <nav className="navbar navbar-dark fixed-top bg-dark shadow">
  <a 
    className="navbar-brand col-sm-3 col-md-2 mr-auto ml-3 d-flex align-items-center"
    href="https://github.com/REVANTH1205" 
    target="_blank" 
    rel="noopener noreferrer"
  >
    {/* Logo Image */}
    <img 
      src={logo}  // ✅ Update this path to your actual logo location
      alt="Logo" 
      style={{ width: '32px', height: '32px', marginRight: '10px', borderRadius: '50%' }}
    />
    LogCrypt - A Blockchain Based Log File Storage System
  </a>

  <ul className="navbar-nav px-3">
    <li className="nav-item text-nowrap">
      <small className="text-white d-flex align-items-center">
        <a 
          href={`https://etherscan.io/address/${this.state.account}`} 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-white text-decoration-none"
          style={{ marginRight: "8px" }}
        >
          {this.state.account ? this.state.account : "0x0"}
        </a>
        <span role="img" aria-label="User" style={{ fontSize: "18px" }}>👨‍💻</span>
      </small>
    </li>
  </ul>
</nav>


      <div className="container-fluid mt-5">
        <div className="row">
          <main role="main" className="col-lg-12 d-flex justify-content-center align-items-center text-center">
            <div className="content mr-auto ml-auto">
              <p>&nbsp;</p>
              {/*<button onClick={this.getRole}>Get Role</button>;*/}
              <h2>Log File Storgae System</h2>
             
              <p>&nbsp;</p>
              <h5>Role: {this.state.userRole}</h5>
              { this.state.userRole === "Admin" && (
              <form onSubmit={this.onSubmit} className="file-input-container">
                <label htmlFor="file-upload" className="file-label">
                  <span role="img" aria-label="Choose File">📂</span> Choose File
                </label>
                <input 
                  id="file-upload" 
                  type="file" 
                  onChange={(event) => {
                    this.captureFile(event);
                    this.setState({ selectedFile: event.target.files[0] });
                  }} 
                  className="custom-file-input" 
                />
                {this.state.selectedFile && (
                  <p className="selected-file">
                    <strong>Selected File:</strong> {this.state.selectedFile.name}
                  </p>
                )}
                <button type="submit" className="upload-button">
                  <span role="img" aria-label="Upload">🚀</span> Upload
                </button>
              </form>
            ) }

              <h2 className="mt-5"><span role="img" aria-label="Choose File">📝 </span> Log Files</h2>
              <p>&nbsp;</p>

              {/* 🔍 Search Bar */}
              <input
                type="text"
                placeholder="🔍 Search files... ( Search By Name , Hash or Timestamp )"
                className="search-bar"
                value={this.state.searchQuery}
                onChange={(event) => this.setState({ searchQuery: event.target.value })}
              />

              <div className="table-responsive">
                <table className="table table-striped">
                  <thead>
                    <tr>
                      <th>File No.</th>
                      <th>File Name</th>
                      <th>IPFS Hash</th>
                      <th>Size </th>
                      <th>Timestamp</th>
                      <th>View</th>
                      <th>Delete</th>
                      <th>Download</th>
                    </tr>
                  </thead>
                  <tbody>
                    {this.state.files
                      .filter(file => 
                        file.fileName.toLowerCase().includes((this.state.searchQuery || '').toLowerCase()) ||
                        file.fileHash.toLowerCase().includes((this.state.searchQuery || '').toLowerCase()) ||
                        new Date(parseInt(file.uploadTime._hex, 16) * 1000).toLocaleString().includes((this.state.searchQuery || ''))
                      )
                      .map((file, index) => (
                        <tr key={index}>
                          <td>{index + 1}</td>
                          <td>{file.fileName}</td>
                          <td 
                            onClick={() => {
                              navigator.clipboard.writeText(file.fileHash);
                              alert("✅ IPFS Hash copied to clipboard!");
                            }} 
                            style={{ cursor: "pointer", color: "#007bff", textDecoration: "underline" }} 
                            title="Click to copy"
                          >
                            {file.fileHash.substring(0, 10)}...
                          </td>
                          <td>{convertBytes(parseInt(file.fileSize._hex, 16))}</td>
                          <td>{new Date(parseInt(file.uploadTime._hex, 16) * 1000).toLocaleString()}</td>
                          <td>
                            <a href={`https://gateway.pinata.cloud/ipfs/${file.fileHash}`} target="_blank" rel="noopener noreferrer">
                              <span role="img" aria-label="Open link">🔗</span> Open
                            </a>
                          </td>
                          <td>
                            <button 
                              onClick={() => {
                                this.deleteFile(parseInt(file.fileId._hex, 16));
                              }} 
                              className="delete-button"
                            >
                              <span role="img" aria-label="Delete">🗑️</span> Delete
                            </button>
                          </td>
                          <td>
                            <button 
                              className="view-button" 
                              onClick={() => this.promptForKeyAndDownload(file.fileHash, file.fileName, file.fileId)}
                            >
                              <span role="img" aria-label="Download">⬇️</span> Decrypt & Verify
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>

              {/* 📜 Audit Log Section (Only for Admins) */}
              {this.state.userRole === "Admin" && (
              <div className="table-responsive mt-5">
                {/* Header Row: Title + Search + Download */}
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <h2>
                    <span role="img" aria-label="Scroll">📜</span> Audit Log
                  </h2>
                  <input
                    type="text"
                    className="form-control w-50"
                    placeholder="🔍 Search Audit Log (Action, Role, File Name, Hash, Timestamp, Address)"
                    value={this.state.auditSearchQuery}
                    onChange={(e) => this.setState({ auditSearchQuery: e.target.value })}
                  />
                  <button
                    className="btn btn-success ml-3"
                    onClick={async () => {
                      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                      const logs = await this.fetchAuditLogs(this.state.contract, accounts[0]);
                      this.downloadAuditLogsCSV(logs);
                    }}
                  >
                    <span role="img" aria-label="Download">⬇️</span> Download Audit Log (CSV)
                  </button>
                </div>

                {/* Audit Log Table */}
                <table className="table table-striped">
                  <thead>
                    <tr>
                      <th>No.</th>
                      <th>User Address</th>
                      <th>User Role</th>
                      <th>Action</th>
                      <th>File Name</th>
                      <th>File Hash</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {this.state.auditLogs
                      .filter((log) => {
                        const query = this.state.auditSearchQuery.toLowerCase();
                        return (
                          log.user.toLowerCase().includes(query) ||
                          (log.userRole || "Normal User").toLowerCase().includes(query) ||
                          log.action.toLowerCase().includes(query) ||
                          log.fileName.toLowerCase().includes(query) ||
                          log.fileHash.toLowerCase().includes(query) ||
                          log.timestamp.toLowerCase().includes(query)
                        );
                      })
                      .map((log, index) => (
                        <tr key={index}>
                          <td>{index + 1}</td>
                          <td>{log.user}</td>
                          <td>{log.userRole || 'Normal User'}</td>
                          <td>{log.action}</td>
                          <td>{log.fileName}</td>
                          <td
                            onClick={() => {
                              navigator.clipboard.writeText(log.fileHash);
                              alert("✅ File Hash copied!");
                            }}
                            style={{ cursor: "pointer", color: "#007bff", textDecoration: "underline" }}
                            title="Click to copy"
                          >
                            {log.fileHash.substring(0, 10)}...
                          </td>
                          <td>{log.timestamp}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}
}
export default App;
