import bsv from 'bsv';
import Mnemonic from 'bsv/mnemonic';
import BufferUtil from 'bsv/lib/util/buffer';
import Hash from 'bsv/lib/crypto/hash';
import BN from 'bsv/lib/crypto/bn';
import Point from 'bsv/lib/crypto/point';

let xpubInput;
let childPrivateKeyInput;
let childDerivationPathInput;
let resultsElement;

window.addEventListener('load', function onContentLoaded(event) {
  init();
});

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
function deriveNormalChildPrivateKey(xprv, index) {
  const exPrvKey = bsv.HDPrivateKey.fromString(xprv);
  const exPrvKeyJson = exPrvKey.toJSON();
  console.log('From xprv:        ', exPrvKeyJson);
  console.log('kpar:             ', exPrvKeyJson.privateKey);

  const i = index;
  const iBuffer = BufferUtil.integerAsBuffer(i);

  const KparBuffer = exPrvKey.publicKey.toBuffer();
  const data = BufferUtil.concat([KparBuffer, iBuffer]);
  console.log('data:             ', data.toString('hex'));
  console.log('Data length:      ', data.length);

  const cparBuffer = Buffer.from(exPrvKeyJson.chainCode, 'hex');
  console.log('Chain code length:', cparBuffer.length);
  console.log('cpar:             ', cparBuffer.toString('hex'));

  const key = cparBuffer;
  const I = Hash.sha512hmac(data, key);
  console.log('I:                ', I.toString('hex'));
  const IL = BN.fromBuffer(I.slice(0, 32), { size: 32 });
  console.log('IL:               ', IL.toString(16));
  const prvKeyNumber = exPrvKey.privateKey.toBigNumber();
  const ILPluskpar = IL.add(prvKeyNumber);
  console.log('ILPluskpar:       ', ILPluskpar.toString(16));
  const n = Point.getN();
  console.log('n:                ', n.toString(16));
  const ki = ILPluskpar.umod(n);

  console.log('ki:               ', ki.toString(16));
  const childPrivateKeyBytes = ki.toBuffer({ size: 32 });
  const childPrivateKeyHex = childPrivateKeyBytes.toString('hex');
  console.log('Private key bytes:', childPrivateKeyHex);

  if (!bsv.PrivateKey.isValid(childPrivateKeyBytes)) {
    console.error('Private key was invalid.');
    return;
  }

  const childPrivateKey = new bsv.PrivateKey(childPrivateKeyHex, 'livenet');
  console.log('childPrivateKey:  ', childPrivateKey);
  
  const childPubKey = childPrivateKey.publicKey;
  const childAddress = childPubKey.toAddress();
  console.log('childAddress:     ', childAddress.toString());

  console.log('ILPluskpar:       ', ILPluskpar.toString(16));
  const withoutRemainder = ILPluskpar.sub(ki);
  console.log('withoutRemainder: ', withoutRemainder.toString(16));

  const withoutPrivateKey = ILPluskpar.sub(prvKeyNumber);
  console.log('withoutPrivateKey:', withoutPrivateKey.toString(16));
}

function init() {
  xpubInput = document.getElementById('xpub');
  childPrivateKeyInput = document.getElementById('child-private-key');
  childDerivationPathInput = document.getElementById('child-derivation-path');
  resultsElement = document.getElementById('results');
  //startInvestigativeCode();
}


// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
function deriveParentPrivateKey(parentXpub, childPrivateKey, childIndex) {
  const exPubKey =  bsv.HDPublicKey.fromString(parentXpub);
  const exPubKeyObject = exPubKey.toObject();
  console.log('exPubKeyObject:', exPubKeyObject);

  const cpar = exPubKeyObject.chainCode;
  const cparBuffer = Buffer.from(cpar, 'hex');
  console.log('cpar:            ', cparBuffer.toString('hex'));

  const Kpar = exPubKey.publicKey;
  const KparBuffer = Kpar.toBuffer();

  const i = childIndex;
  const iBuffer = BufferUtil.integerAsBuffer(i);

  const data = BufferUtil.concat([KparBuffer, iBuffer]);
  console.log('data:            ', data.toString('hex'));
  const key = cparBuffer;

  const I = Hash.sha512hmac(data, key);

  const IL = BN.fromBuffer(I.slice(0, 32), { size: 32 });
  console.log('IL:              ', IL.toString(16));

  const n = Point.getN();
  const ki = childPrivateKey.toBigNumber();
  console.log('ki:              ', ki.toString(16));

  let ILPluskparCandidate = ki;

  // TODO: Use proper limit
  let j;
  for (j = 0; j < 3; j++) {
    const kparCandidate = ILPluskparCandidate.sub(IL);

    if (kparCandidate.gt(new BN(0))) {
      const kparCandidateHex = kparCandidate.toString(16);
      console.log('kparCandidateHex:', kparCandidateHex);
      let privKeyCandidate;
      try {
        privKeyCandidate = new bsv.PrivateKey(kparCandidateHex, 'livenet');
      } catch (e) {
        console.error(e);
        ILPluskparCandidate = ILPluskparCandidate.add(n);
        continue
      }
      const pubKeyCandidate = privKeyCandidate.publicKey;
      const pubKeyCandidateDer = pubKeyCandidate.toHex();
      console.log('pubKeyCandidate: ', pubKeyCandidate.toHex());
      if (pubKeyCandidateDer === exPubKeyObject.publicKey) {
        console.log("FOUND");

        const parentExPrvKey = new bsv.HDPrivateKey({
          network: exPubKeyObject.network,
          depth: exPubKeyObject.depth,
          parentFingerPrint: exPubKeyObject.parentFingerPrint,
          childIndex: exPubKeyObject.childIndex,
          chainCode: exPubKeyObject.chainCode,
          privateKey: privKeyCandidate.toBuffer()
        });

        console.log('xprv:', parentExPrvKey.toString());
        console.log('xprv:', parentExPrvKey.toObject());

        return parentExPrvKey;
      }
    }

    ILPluskparCandidate = ILPluskparCandidate.add(n);
  }
}

function generateAndDisplayResults(xprv) {

  // Clear any previous results
  const prevTable = document.getElementById('results-table');
  if (prevTable) {
    resultsElement.removeChild(prevTable);
  }
  
  const xprvElement = document.getElementById('xprv');

  xprvElement.innerText = `xprv: ${xprv}`;

  const parentHdPriv = new bsv.HDPrivateKey(xprv);
  const pkElement = document.getElementById('private-key');
  pkElement.innerText = `Parent private key: ${parentHdPriv.privateKey.toString()}`;

  const table = document.createElement('table');
  table.id = 'results-table';

  const headerRow = document.createElement('tr');
  const pathHeader = document.createElement('th');
  pathHeader.innerText = 'Path';
  const addressHeader = document.createElement('th');
  addressHeader.innerText = 'Address';
  const derHeader = document.createElement('th');
  derHeader.innerText = 'Public Key';
  const wifHeader = document.createElement('th');
  wifHeader.innerText = 'Private Key';
  headerRow.appendChild(pathHeader);
  headerRow.appendChild(addressHeader);
  headerRow.appendChild(derHeader);
  headerRow.appendChild(wifHeader);
  table.appendChild(headerRow);

  let i;
  for (i = 0; i < 5; i++) {
    const derivationPath = `m/${i}`;
    const child = parentHdPriv.deriveChild(derivationPath);
    const address = child.publicKey.toAddress().toString();
    const der = child.publicKey.toString();
    const wif = child.privateKey.toWIF();
    console.log(`${derivationPath} ${address} ${der} ${wif}`);
    const row = document.createElement('tr');
    const pathCell = document.createElement('td');
    pathCell.innerText = derivationPath;
    const addressCell = document.createElement('td');
    addressCell.innerText = address;
    const derCell = document.createElement('td');
    derCell.innerText = der;
    const wifCell = document.createElement('td');
    wifCell.innerText = wif;
    row.appendChild(pathCell);
    row.appendChild(addressCell);
    row.appendChild(derCell);
    row.appendChild(wifCell);
    table.appendChild(row);
  }

  resultsElement.appendChild(table);

  resultsElement.style = "display: block";
}


function startInvestigativeCode() {
  console.log('startInvestigativeCode()');
  const mnemonic = Mnemonic.fromString('cotton job error bullet math manage monkey shrimp taste display knock roof require follow idea');
  console.log('mnemonic:', mnemonic.toString());

  const seed = mnemonic.toSeed();
  const hdPrivateKey = bsv.HDPrivateKey.fromSeed(seed);
  console.log('master:', hdPrivateKey.toString());

  const external = hdPrivateKey.deriveChild("m/44'/0'/0'/0");
  const externalXprv = external.toString();
  console.log('external:', externalXprv);
  const externalXpub = external.xpubkey;
  console.log('external:', externalXpub);

  const child = external.deriveChild('m/1');
  const childHdPubKey = child.hdPublicKey;
  console.log('child pub:', childHdPubKey.publicKey.toString()); // matches
  const childAddr = childHdPubKey.publicKey.toAddress();
  console.log('child add:',childAddr.toString());
  const childPrivKey = child.privateKey;
  console.log('child WIF:', childPrivKey.toString());
  console.log('child hex:', childPrivKey.toHex());
  
  deriveNormalChildPrivateKey(externalXprv, 1);
  deriveParentPrivateKey(externalXpub, childPrivKey, 1); 
}


export function onFillWithSampleData() {
  xpubInput.value = 'xpub6E44V8RGiA8bFR1mwSWZ3yTLbnGMHCWsdeCr4jZRk1Qn6SfSpCYNyxw6NAcnNNLR5MfkRtVVn3ooTxHCCvh4xy3zUL2iBFdChheRZ8seWKV';
  childPrivateKeyInput.value = 'KznyqyyNnNJuM7szyau7gP9GcJE5J22RMGXU7aZpGuXFhxiqT4pp';
  childDerivationPathInput.value = 'm/4';
}


export function onFormSubmit() {
  console.log('onFormSubmit()');
  event.preventDefault();
  resultsElement.style = "display:none";

  const xpub = xpubInput.value;
  const childPrivateKeyText = childPrivateKeyInput.value;
  const childDerivationPath = childDerivationPathInput.value;

  console.log('xpub:                ', xpub);
  console.log('childPrivateKeyText: ', childPrivateKeyText);
  console.log('childDerivationPath: ', childDerivationPath);

  // Prepare input
  const pathParts = childDerivationPath.split('/');
  const parentPathParts = pathParts.slice(0, Math.max(0, pathParts.length - 1));
  const parentPath = parentPathParts.join('/');
  console.log('Parent path:         ', parentPath);

  let immediateParentXpub = xpub;
  if (parentPath !== 'm/') {
    const rootPublicKey = bsv.HDPublicKey.fromString(xpub);
    const immediateParent = rootPublicKey.deriveChild(parentPath);
    immediateParentXpub = immediateParent.toString();
    console.log('immediateParent xpub:', immediateParentXpub);
  }
  const childIndexText = pathParts.slice(pathParts.length - 1);
  console.log('childIndexText:      ', childIndexText);
  const childIndexNumber = Number(childIndexText);
  const childPrivateKey = new bsv.PrivateKey(childPrivateKeyText, 'livenet');
  console.log('childIndexNumber:    ', childIndexNumber);

  // Process the formatted input
  const xprv = deriveParentPrivateKey(immediateParentXpub, childPrivateKey, childIndexNumber)
  if (xprv) {
    generateAndDisplayResults(xprv)
  } else {
    alert('Failed to derive a match.');
  }
}