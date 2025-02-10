// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}


// OpenZeppelin ERC20 Implementation
contract ERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;
    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
        }
        _balances[to] += amount;

        emit Transfer(from, to, amount);
    }

    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}

// OpenZeppelin ERC721 Implementation
contract ERC721 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    string private _name;
    string private _symbol;

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function name() public view virtual returns (string memory) {
        return _name;
    }

    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    function balanceOf(address owner) public view virtual returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view virtual returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    function approve(address to, uint256 tokenId) public virtual {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(
            msg.sender == owner || isApprovedForAll(owner, msg.sender),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    function getApproved(uint256 tokenId) public view virtual returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");
        return _tokenApprovals[tokenId];
    }

    function setApprovalForAll(address operator, bool approved) public virtual {
        _setApprovalForAll(msg.sender, operator, approved);
    }

    function isApprovedForAll(address owner, address operator) public view virtual returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function transferFrom(address from, address to, uint256 tokenId) public virtual {
        require(_isApprovedOrOwner(msg.sender, tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual {
        safeTransferFrom(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public virtual {
        require(_isApprovedOrOwner(msg.sender, tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory _data) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
    }

    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    function _setApprovalForAll(address owner, address operator, bool approved) internal virtual {
        require(owner != operator, "ERC721: approve to caller");
        _operatorApprovals[owner][operator] = approved;
        emit ApprovalForAll(owner, operator, approved);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data) private returns (bool) {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver.onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }
    
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, ""), "ERC721: transfer to non ERC721Receiver implementer");
    }

}

// OpenZeppelin Ownable Implementation
contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _transferOwnership(msg.sender);
    }

    function owner() public view virtual returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// DonationToken Contract
contract DonationToken is ERC20 {
    constructor(uint256 initialSupply) ERC20("DonationToken", "DNT") {
        _mint(msg.sender, initialSupply);
    }
}

// DonationNFT Contract
contract DonationNFT is ERC721, Ownable {
    uint256 private _tokenIds;
    mapping(address => bool) public validCharities;
    address charityFactoryAddress;

    constructor() ERC721("DonationNFT", "DNFT") {}

    function mintDonationNFT(address _to, uint256 _donationAmount) external returns (uint256) {
        require(validCharities[msg.sender], "Only valid charity contracts can mint"); 
        require(_donationAmount > 0, "A donation must be made");

        _tokenIds += 1;
        _safeMint(_to, _tokenIds);
        return _tokenIds;
    }

    function setCharityFactory(address _charityFactory) public onlyOwner {
        charityFactoryAddress = _charityFactory;
    }

    function addValidCharity(address charity) external {
        require(msg.sender == charityFactoryAddress, "Only CharityFactory can add valid charities");
        validCharities[charity] = true;
    }
}

// TrustlessDonation Contract
contract TrustlessDonation {
    DonationToken private _donationToken;
    DonationNFT private _donationNFT;
    string public charityName;
    uint public totalDonations;
    address public charityOwner;

    mapping(address => bool) suppliers;
    address[] public supplierList;
    
    event Donation(address indexed donor, address indexed charity, uint256 amount, uint256 tokenId);
    event Purchase(address indexed charity, address indexed supplier, uint256 amount);
    event CharityNameChanged(address indexed charity, string newName);
    event SupplierRegistered(address indexed charity, address indexed supplier);
    event SupplierRemoved(address indexed charity, address indexed supplier);

    constructor(DonationToken donationToken, DonationNFT donationNFT, address _charityOwner, string memory _charityName) {
        _donationToken = donationToken;
        _donationNFT = donationNFT;
        charityOwner = _charityOwner;
        charityName = _charityName;
    }

    modifier onlyCharityOwner() {
        require(msg.sender == charityOwner, "Caller is not the charity owner");
        _;
    }

    function setCharityName(string memory _charityName) external onlyCharityOwner {
        charityName = _charityName;
        emit CharityNameChanged(msg.sender, _charityName);
    }

    function registerSupplier(address _supplier) external onlyCharityOwner {
        suppliers[_supplier] = true;
        supplierList.push(_supplier);
        emit SupplierRegistered(msg.sender, _supplier);
    }
    
    function removeSupplier(address _supplier) external onlyCharityOwner {
        suppliers[_supplier] = false;
        for (uint i = 0; i < supplierList.length; i++) {
            if (supplierList[i] == _supplier) {
                supplierList[i] = supplierList[supplierList.length - 1];
                supplierList.pop();
                break;
            }
        }
        emit SupplierRemoved(msg.sender, _supplier);
    }

    function getRegisteredSuppliers() external view returns (address[] memory) {
        return supplierList;
    }

    function donate(uint256 amount) external {
        require(_donationToken.transferFrom(msg.sender, address(this), amount), "Donation failed");
        
        uint256 tokenId = _donationNFT.mintDonationNFT(msg.sender, amount);

        totalDonations += amount;
        
        emit Donation(msg.sender, address(this), amount, tokenId);
    }
    
    function purchase(address supplier, uint256 amount) external onlyCharityOwner {
        require(suppliers[supplier], "Invalid supplier");
        
        require(_donationToken.transfer(supplier, amount), "Purchase failed");

        totalDonations -= amount;

        emit Purchase(msg.sender, supplier, amount);
    }
}

// CharityFactory Contract
contract CharityFactory is Ownable {
    DonationToken private _donationToken;
    DonationNFT private _donationNFT;
    mapping(address => TrustlessDonation) public charityContracts;
    event CharityCreated(address creator, address charity, string name);

    constructor(DonationToken donationToken, DonationNFT donationNFT) {
        _donationToken = donationToken;
        _donationNFT = donationNFT;
    }

    function createCharityContract(string memory charityName) external {
        require(address(charityContracts[msg.sender]) == address(0), "User already has a charity contract");
        TrustlessDonation newCharity = new TrustlessDonation(_donationToken, _donationNFT, msg.sender, charityName);
        charityContracts[msg.sender] = newCharity;
        _donationNFT.addValidCharity(address(newCharity)); // update the validCharities mapping in DonationNFT
        
        emit CharityCreated(msg.sender, address(newCharity), charityName);
    }
}