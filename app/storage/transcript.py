"""
Manages session transcripts for non-repudiation.

- Each session gets a unique transcript file.
- Messages are appended and hashed.
- Final SHA-256 hash can be retrieved for receipt verification.
"""

import hashlib
import pathlib
from app.common.utils import now_ms

TRANSCRIPT_DIR = pathlib.Path(__file__).parent.parent.parent / "transcripts"

class Transcript:
    """
    Logs all session messages and computes the transcript hash.
    """
    
    def __init__(self, peer_name: str, peer_cn: str):
        """
        Create a new transcript file and hash object.
        
        Args:
            peer_name: "client" or "server"
            peer_cn: CN of the other party (used in filename)
        """
        TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
        
        timestamp = now_ms()
        safe_cn = peer_cn.replace(".", "_")
        self.filename = f"{peer_name}_vs_{safe_cn}_{timestamp}.log"
        self.filepath = TRANSCRIPT_DIR / self.filename
        
        self.hash_obj = hashlib.sha256()
        
        try:
            self.file_handle = open(self.filepath, "w", encoding="utf-8")
            print(f"[Transcript] Session logging started: {self.filename}")
        except IOError as e:
            print(f"Error creating transcript file {self.filepath}: {e}")
            raise

    def log_message(self, sender_cn: str, seqno: int, ts: int, ct: str, sig: str):
        """
        Append a message to the transcript and update hash.
        
        Args:
            sender_cn: CN of message sender
            seqno: sequence number
            ts: timestamp in ms
            ct: base64 ciphertext
            sig: base64 signature
        """
        line = f"{seqno}|{ts}|{ct}|{sig}|{sender_cn}\n"
        try:
            self.file_handle.write(line)
            self.hash_obj.update(line.encode('utf-8'))
        except IOError as e:
            print(f"Error writing to transcript: {e}")

    def finalize(self) -> tuple[str, str]:
        """
        Close the transcript and return its SHA-256 hash.
        
        Returns:
            (hash_hex, transcript_filepath)
        """
        try:
            self.file_handle.close()
            final_hash = self.hash_obj.hexdigest()
            print(f"[Transcript] Final hash: {final_hash}")
            return final_hash, str(self.filepath)
        except IOError as e:
            print(f"Error finalizing transcript: {e}")
            return "ERROR_FINALIZING", str(self.filepath)
