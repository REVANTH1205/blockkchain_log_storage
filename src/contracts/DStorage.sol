pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;


contract DStorage {
    string public name = "DStorage";
    uint public fileCount = 0;
    mapping(uint => File) public files;
    mapping(uint => bytes32) public fileIntegrityHashes;
    mapping(address => string) public roles; // Role-Based Access Control

    struct File {
        uint fileId;
        string fileHash;
        uint fileSize;
        string fileType;
        string fileName;
        string fileDescription;
        uint uploadTime;
        address payable uploader;
    }

    // 🛡️ Audit Log Structure
    struct AuditLog {
        uint timestamp;
        address user;
        string userRole;
        string action;
        string fileName;
        string fileHash;
    }

    AuditLog[] public auditLogs; // Array to store audit logs

    // 📌 Events
    event FileUploaded(uint fileId, string fileHash, uint fileSize, string fileType, string fileName, string fileDescription, uint uploadTime, address payable uploader);
    event FileDeleted(uint fileId, string fileName, address deletedBy);
    event FileViewed(uint fileId, string fileName, address viewedBy);
    event RoleAssigned(address indexed user, string role);
    event ActionLogged(uint timestamp, address user, string userRole, string action, string fileName, string fileHash); // Audit Log Event

    constructor() public {
        roles[msg.sender] = "Admin"; // Contract deployer is Admin
    }

    // 🔑 Modifiers
    modifier onlyAdmin() {
        require(keccak256(bytes(roles[msg.sender])) == keccak256(bytes("Admin")), "Access Denied: Not an Admin");
        _;
    }

    modifier onlyUserOrAdmin() {
        require(
            keccak256(bytes(roles[msg.sender])) == keccak256(bytes("Admin")) || 
            keccak256(bytes(roles[msg.sender])) == keccak256(bytes("User")), 
            "Access Denied: Not a User or Admin"
        );
        _;
    }

    modifier onlyUploaderOrAdmin(uint _fileId) {
        require(
            msg.sender == files[_fileId].uploader || keccak256(bytes(roles[msg.sender])) == keccak256(bytes("Admin")),
            "Access Denied: Only uploader or Admin can delete"
        );
        _;
    }

    // 👤 Assign Roles
    function setRole(address _user, string memory _role) public onlyAdmin {
        require(
            keccak256(bytes(_role)) == keccak256(bytes("Admin")) ||
            keccak256(bytes(_role)) == keccak256(bytes("User")) ||
            keccak256(bytes(_role)) == keccak256(bytes("Viewer")), 
            "Invalid Role: Use 'Admin', 'User', or 'Viewer'"
        );
        roles[_user] = _role;
        emit RoleAssigned(_user, _role);
    }

    function getRole(address _user) public view returns (string memory) {
        return roles[_user];
    }

    // 📂 Upload File (Logs Upload Action)
    function uploadFile(string memory _fileHash, uint _fileSize, string memory _fileType, string memory _fileName, string memory _fileDescription, bytes32 _integrityHash) public onlyUserOrAdmin {
        require(bytes(_fileHash).length > 0, "Invalid file hash");
        require(bytes(_fileType).length > 0, "Invalid file type");
        require(bytes(_fileDescription).length > 0, "Invalid file description");
        require(bytes(_fileName).length > 0, "Invalid file name");
        require(msg.sender != address(0), "Invalid uploader address");
        require(_fileSize > 0, "Invalid file size");

        fileCount++;
        files[fileCount] = File(fileCount, _fileHash, _fileSize, _fileType, _fileName, _fileDescription, block.timestamp, msg.sender);
        fileIntegrityHashes[fileCount] = _integrityHash;

        // 📝 Log Upload Action
        auditLogs.push(AuditLog(block.timestamp, msg.sender, roles[msg.sender], "Uploaded", _fileName, _fileHash));
        emit ActionLogged(block.timestamp, msg.sender, roles[msg.sender], "Uploaded", _fileName, _fileHash);

        emit FileUploaded(fileCount, _fileHash, _fileSize, _fileType, _fileName, _fileDescription, block.timestamp, msg.sender);
    }

    // 🔍 View File (Logs View Action)
    function viewFile(uint _fileId) public {
        require(_fileId > 0 && _fileId <= fileCount, "Invalid file ID");

        File memory file = files[_fileId];
        
        // 📝 Log View Action
        auditLogs.push(AuditLog(block.timestamp, msg.sender, roles[msg.sender], "Viewed", file.fileName, file.fileHash));
        emit ActionLogged(block.timestamp, msg.sender, roles[msg.sender], "Viewed", file.fileName, file.fileHash);

        emit FileViewed(_fileId, file.fileName, msg.sender);
    
    }

     // 🧾 Record Download (NEW)
    function recordDownload(uint _fileId) public {
        require(_fileId > 0 && _fileId <= fileCount, "Invalid file ID");
        File memory file = files[_fileId];

        auditLogs.push(AuditLog(block.timestamp, msg.sender, roles[msg.sender], "Downloaded", file.fileName, file.fileHash));
        emit ActionLogged(block.timestamp, msg.sender, roles[msg.sender], "Downloaded", file.fileName, file.fileHash);
    }

    //  Get File Integrity Hash
    function getFileIntegrityHash(uint _fileId) public view returns (bytes32) {
        require(_fileId > 0 && _fileId <= fileCount, "Invalid file ID");
        return fileIntegrityHashes[_fileId];
    }

    //  Verify File Integrity
    function verifyFileIntegrity(uint _fileId, bytes32 _computedHash) public view returns (bool) {
        require(_fileId > 0 && _fileId <= fileCount, "Invalid file ID");
        return fileIntegrityHashes[_fileId] == _computedHash;
    }

    // 🗑️ Delete File (Logs Delete and Unauthorized Delete Attempt)
    function deleteFile(uint _fileId) public onlyUploaderOrAdmin(_fileId) {
        require(_fileId > 0 && _fileId <= fileCount, "Invalid file ID");

        File memory file = files[_fileId];

        files[_fileId].fileHash = "";
        files[_fileId].fileName = "Deleted File";
        files[_fileId].fileDescription = "This file has been deleted.";
        files[_fileId].fileSize = 0;
        files[_fileId].uploadTime = 0;

        delete fileIntegrityHashes[_fileId]; 
        
        // 📝 Log Delete Action
        auditLogs.push(AuditLog(block.timestamp, msg.sender, roles[msg.sender], "Deleted", file.fileName, file.fileHash));
        emit ActionLogged(block.timestamp, msg.sender, roles[msg.sender], "Deleted", file.fileName, file.fileHash);

        emit FileDeleted(_fileId, file.fileName, msg.sender);
    }

    // 📜 Get Audit Logs (Only Admin Can View)
    function getAuditLogs() public view onlyAdmin returns (
        uint[] memory,
        address[] memory,
        string[] memory,
        string[] memory,
        string[] memory,
        string[] memory
    ) {
        uint len = auditLogs.length;
        uint[] memory timestamps = new uint[](len);
        address[] memory users = new address[](len);
        string[] memory rolesList = new string[](len);
        string[] memory actions = new string[](len);
        string[] memory fileNames = new string[](len);
        string[] memory fileHashes = new string[](len);

        for (uint i = 0; i < len; i++) {
            AuditLog storage log = auditLogs[i];
            timestamps[i] = log.timestamp;
            users[i] = log.user;
            rolesList[i] = log.userRole;
            actions[i] = log.action;
            fileNames[i] = log.fileName;
            fileHashes[i] = log.fileHash;
        }

        return (timestamps, users, rolesList, actions, fileNames, fileHashes);
    }


}
