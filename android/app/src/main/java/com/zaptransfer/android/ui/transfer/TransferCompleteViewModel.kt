package com.zaptransfer.android.ui.transfer

import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.zaptransfer.android.data.db.dao.TransferHistoryDao
import com.zaptransfer.android.navigation.ARG_TRANSFER_ID
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

private const val TAG = "TransferCompleteViewModel"

/**
 * UI state for [TransferCompleteSheet].
 *
 * @param fileName      Original filename of the transferred file.
 * @param fileSizeBytes File size in bytes for the size label.
 * @param localUri      Content URI string of the completed file on this device.
 *                      Null until the history record is loaded or while moving.
 * @param mimeType      MIME type for [Intent.ACTION_VIEW]; null falls back to "*\/*".
 */
data class TransferCompleteUiState(
    val fileName: String = "",
    val fileSizeBytes: Long = 0L,
    val localUri: String? = null,
    val mimeType: String? = null,
)

/**
 * ViewModel for [TransferCompleteSheet].
 *
 * Loads the transfer record from [TransferHistoryDao] using the [ARG_TRANSFER_ID]
 * argument extracted from [SavedStateHandle]. Exposes save-to-location actions that
 * copy the file via MediaStore or a SAF URI.
 *
 * @param savedStateHandle  Provides the transferId from the nav back-stack entry.
 * @param historyDao        Room DAO to load the completed transfer's metadata.
 * @param context           Application context for MediaStore + ContentResolver access.
 */
@HiltViewModel
class TransferCompleteViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val historyDao: TransferHistoryDao,
    @ApplicationContext private val context: Context,
) : ViewModel() {

    private val transferId: String = checkNotNull(savedStateHandle[ARG_TRANSFER_ID])

    private val _uiState = MutableStateFlow(TransferCompleteUiState())
    val uiState: StateFlow<TransferCompleteUiState> = _uiState.asStateFlow()

    init {
        loadTransferRecord()
    }

    private fun loadTransferRecord() {
        viewModelScope.launch {
            val record = historyDao.getById(transferId)
            if (record != null) {
                _uiState.value = TransferCompleteUiState(
                    fileName = record.fileName,
                    fileSizeBytes = record.fileSizeBytes,
                    localUri = record.localUri,
                    mimeType = record.mimeType,
                )
            } else {
                Log.w(TAG, "No history record found for transferId=$transferId")
            }
        }
    }

    /**
     * Copies the completed file to the system Downloads folder via MediaStore.
     *
     * Uses [MediaStore.Downloads] (API 29+) for proper scoped-storage compliance.
     * The file remains in the app's external-files directory as well (original location).
     *
     * @param transferId UUID of the completed transfer (used only for logging).
     */
    fun saveToDownloads(transferId: String) {
        viewModelScope.launch {
            val state = _uiState.value
            val sourceUri = state.localUri ?: run {
                Log.w(TAG, "saveToDownloads: no localUri for $transferId")
                return@launch
            }
            try {
                val sourceFile = File(android.net.Uri.parse(sourceUri).path ?: return@launch)
                if (!sourceFile.exists()) {
                    Log.w(TAG, "saveToDownloads: source file does not exist: $sourceFile")
                    return@launch
                }

                val contentValues = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, state.fileName)
                    put(MediaStore.MediaColumns.MIME_TYPE, state.mimeType ?: "application/octet-stream")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val resolver = context.contentResolver
                val destUri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, contentValues)
                if (destUri == null) {
                    Log.e(TAG, "MediaStore insert returned null URI")
                    return@launch
                }
                resolver.openOutputStream(destUri)?.use { out ->
                    sourceFile.inputStream().use { inp -> inp.copyTo(out) }
                }
                Log.i(TAG, "File saved to Downloads: ${state.fileName}")
            } catch (e: Exception) {
                Log.e(TAG, "saveToDownloads failed: ${e.message}", e)
            }
        }
    }

    /**
     * Copies the completed file to a user-chosen location via SAF tree URI.
     *
     * @param transferId    UUID of the completed transfer (logging only).
     * @param treeUriString SAF content tree URI string obtained from the system directory picker.
     *                      An empty string is a no-op (user dismissed the picker).
     */
    fun saveToCustomLocation(transferId: String, treeUriString: String) {
        if (treeUriString.isBlank()) return
        viewModelScope.launch {
            val state = _uiState.value
            val sourceUri = state.localUri ?: return@launch
            try {
                val treeUri = android.net.Uri.parse(treeUriString)
                val docTree = androidx.documentfile.provider.DocumentFile.fromTreeUri(context, treeUri)
                val destDoc = docTree?.createFile(
                    state.mimeType ?: "application/octet-stream",
                    state.fileName,
                ) ?: run {
                    Log.e(TAG, "Failed to create document in tree: $treeUriString")
                    return@launch
                }
                val sourceFile = File(android.net.Uri.parse(sourceUri).path ?: return@launch)
                context.contentResolver.openOutputStream(destDoc.uri)?.use { out ->
                    sourceFile.inputStream().use { inp -> inp.copyTo(out) }
                }
                Log.i(TAG, "File saved to custom location: ${state.fileName} → $treeUriString")
            } catch (e: Exception) {
                Log.e(TAG, "saveToCustomLocation failed: ${e.message}", e)
            }
        }
    }
}
