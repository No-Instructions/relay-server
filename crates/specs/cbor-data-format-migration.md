# Architecture Change Request: Migration from Bincode to CBOR for Data Persistence

**Status**: Draft  
**Author**: System Analysis  
**Date**: 2025-08-28  
**Related Components**: `y-sweet-core::sync_kv`, `y-sweet-core::store`

## Executive Summary

This ACR proposes migrating Y-Sweet's data persistence layer from bincode to CBOR (Concise Binary Object Representation) format to enable extensible metadata storage and improve interoperability. The change primarily affects the `SyncKv` implementation in `y-sweet-core/src/sync_kv.rs` and introduces an extension trait for clean BTreeMap serialization.

## Background

### Current Implementation

Y-Sweet currently uses bincode for serializing key-value data in the `SyncKv` component:

- **Location**: `y-sweet-core/src/sync_kv.rs:33,61`
- **Current format**: `bincode::serialize()` and `bincode::deserialize()`
- **Data structure**: `BTreeMap<Vec<u8>, Vec<u8>>` serialized as binary blob
- **Storage key**: `{doc_id}/data.ysweet`

### Analysis of Current Data Flow

1. **Persistence**: `SyncKv::persist()` serializes in-memory `BTreeMap` using bincode
2. **Loading**: `SyncKv::new()` deserializes bincode data back to `BTreeMap`
3. **Storage**: Data stored via `Store::set()` and `Store::get()` as `Vec<u8>`
4. **Backends**: Supports filesystem and S3-compatible storage

## Problem Statement

The current bincode implementation has several limitations:

1. **Lack of Extensibility**: No mechanism to add metadata without breaking existing data
2. **Schema Dependency**: Bincode requires compile-time knowledge of data structure
3. **Limited Interoperability**: Bincode is Rust-specific, limiting cross-language access
4. **No Version Management**: Unable to handle schema evolution gracefully
5. **Missing Metadata**: Cannot store creation timestamps, version info, or other metadata
6. **Tool Visibility**: External tools cannot inspect or modify the BTreeMap structure

## Proposed Solution

### CBOR Format Benefits

CBOR provides several advantages over bincode:

- **IETF Standard**: RFC 8949 specification with broad language support
- **Self-Describing**: Schema-less decoding capability
- **Extensibility**: Built-in tag system for metadata and future expansion
- **Interoperability**: Cross-language compatibility and tool readability
- **Metadata Support**: Rich type information embedded in format

### Architecture Design

The solution uses a two-layer approach:

1. **Extension Trait**: Handles BTreeMap ↔ CBOR map conversion
2. **Metadata Wrapper**: SyncKv manages versioning, timestamps, and extensible metadata

#### Layer 1: BTreeMap CBOR Extension

```rust
trait CborBTreeMapExt {
    fn to_cbor_value(&self) -> ciborium::value::Value;
    fn from_cbor_value(value: ciborium::value::Value) -> Result<Self, Error>;
}

impl CborBTreeMapExt for BTreeMap<Vec<u8>, Vec<u8>> {
    fn to_cbor_value(&self) -> ciborium::value::Value {
        let cbor_map = self.iter()
            .map(|(k, v)| (
                ciborium::value::Value::Bytes(k.clone()),
                ciborium::value::Value::Bytes(v.clone())
            ))
            .collect();
        ciborium::value::Value::Map(cbor_map)
    }
    
    fn from_cbor_value(value: ciborium::value::Value) -> Result<Self, Error> {
        if let ciborium::value::Value::Map(cbor_map) = value {
            let mut btree = BTreeMap::new();
            for (k, v) in cbor_map {
                if let (Value::Bytes(key), Value::Bytes(val)) = (k, v) {
                    btree.insert(key, val);
                }
            }
            Ok(btree)
        } else {
            Err("Expected CBOR map")
        }
    }
}
```

#### Layer 2: Metadata Container

```rust
#[derive(Serialize, Deserialize)]
struct YSweetData {
    /// Format version for future compatibility
    version: u32,
    
    /// Creation timestamp (milliseconds since epoch)
    created_at: u64,
    
    /// Last modified timestamp (milliseconds since epoch)  
    modified_at: u64,
    
    /// Optional metadata for future extensions
    metadata: Option<BTreeMap<String, ciborium::value::Value>>,
    
    /// The actual key-value data as CBOR map
    #[serde(with = "cbor_btreemap")]
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}
```

### Benefits of This Approach

1. **Clean Separation**: Extension trait handles serialization, SyncKv handles metadata
2. **Tool Readability**: CBOR maps can be inspected by generic CBOR tools
3. **Performance**: Maintains BTreeMap's O(log n) operations in memory
4. **Extensibility**: Easy to add new metadata without breaking changes
5. **Reusability**: Extension trait can be used elsewhere in the codebase

## Implementation Plan

#### Phase 1: Add Extension Trait
- Create `CborBTreeMapExt` trait in `y-sweet-core/src/sync_kv.rs`
- Implement CBOR map conversion functions
- Add comprehensive unit tests

#### Phase 2: Implement Metadata Container  
- Define `YSweetData` struct with version and metadata fields
- Update `SyncKv::persist()` to use new format
- Update `SyncKv::new()` with migration logic

#### Phase 3: Migration Strategy
- Implement format detection (CBOR vs bincode)
- Auto-migrate existing bincode data on first write
- Add migration logging and metrics

#### Phase 4: Testing & Cleanup
- Integration tests with real-world data
- Performance benchmarking
- Remove bincode dependency after migration period

### Code Changes Required

#### Modified Files
- `y-sweet-core/src/sync_kv.rs`: Core implementation
- `y-sweet-core/Cargo.toml`: Dependencies (ciborium already present)

#### New Implementation

```rust
impl SyncKv {
    async fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        let data = self.data.lock().unwrap();
        let now = chrono::Utc::now().timestamp_millis() as u64;
        
        let y_data = YSweetData {
            version: 1,
            created_at: self.created_at.unwrap_or(now),
            modified_at: now,
            metadata: None,
            data: data.clone(),
        };
        
        let bytes = ciborium::ser::to_vec(&y_data)?;
        tracing::info!(size = bytes.len(), "Persisting CBOR snapshot");
        
        if let Some(store) = &self.store {
            store.set(&self.key, bytes).await?;
        }
        self.dirty.store(false, Ordering::Relaxed);
        Ok(())
    }
    
    async fn new<Callback: Fn() + Send + Sync + 'static>(
        store: Option<Arc<Box<dyn Store>>>,
        key: &str,
        callback: Callback,
    ) -> Result<Self> {
        let key = format!("{}/data.ysweet", key);
        let mut created_at = None;

        let data = if let Some(store) = &store {
            if let Some(snapshot) = store.get(&key).await.context("Failed to get from store.")? {
                tracing::info!(size = snapshot.len(), "Loading snapshot");
                
                // Try CBOR format first
                match ciborium::de::from_slice::<YSweetData>(&snapshot) {
                    Ok(y_data) => {
                        created_at = Some(y_data.created_at);
                        tracing::info!("Loaded CBOR format data");
                        y_data.data
                    },
                    Err(_) => {
                        // Fallback to bincode for backward compatibility
                        tracing::info!("Falling back to bincode format, will migrate on next persist");
                        bincode::deserialize(&snapshot).context("Failed to deserialize.")?
                    }
                }
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            store,
            key,
            dirty: AtomicBool::new(false),
            dirty_callback: Box::new(callback),
            created_at,
        })
    }
}
```

## Migration Strategy

### Backward Compatibility

1. **Format Detection**: Attempt CBOR deserialization first, fallback to bincode
2. **Lazy Migration**: Convert bincode data to CBOR on first write operation
3. **Graceful Degradation**: Handle corrupted data gracefully
4. **Migration Logging**: Track migration progress and performance

### Data Structure Evolution

The CBOR format enables future enhancements:
- **Document Metrics**: Track operation counts, size changes
- **User Attribution**: Store author information for collaborative features
- **Compression**: Add compression metadata and handling
- **Encryption**: Metadata-aware encryption strategies

## Performance Impact

### Expected Changes
- **Serialization**: CBOR ~2x slower than bincode (acceptable for persistence operations)
- **Deserialization**: CBOR ~2x slower than bincode  
- **Size**: CBOR data ~10-20% larger due to self-describing format and metadata
- **Memory**: Minimal additional memory for metadata fields

### Mitigation Strategies
- Lazy evaluation of metadata fields
- Optional metadata to minimize overhead for small documents
- Background persistence to avoid blocking operations

## Risk Assessment

### High Risk
- **Data Corruption**: During migration from bincode to CBOR
- **Performance Regression**: Slower persistence operations

### Medium Risk  
- **Migration Complexity**: Large existing datasets with edge cases
- **Cross-Version Compatibility**: Mixed format environments

### Low Risk
- **Dependency Issues**: ciborium library already included
- **Tool Integration**: CBOR tooling availability

### Risk Mitigation
- Extensive testing with production data samples
- Staged rollout with feature flags
- Comprehensive backup strategy
- Monitoring and alerting for migration issues

## Testing Strategy

1. **Unit Tests**: Extension trait serialization round-trips
2. **Integration Tests**: Full SyncKv persistence cycle with metadata
3. **Migration Tests**: Bincode → CBOR conversion validation
4. **Performance Tests**: Benchmark against current bincode implementation
5. **Compatibility Tests**: Cross-version data access scenarios
6. **Tool Tests**: Verify external CBOR tool can read/modify data

## Success Metrics

- Zero data loss during migration
- Performance degradation <50% (acceptable for persistence operations)
- Successful metadata extensibility demonstration  
- External CBOR tools can inspect data structure
- Backward compatibility maintained for migration period

## Timeline

- **Week 1**: Extension trait implementation and unit tests
- **Week 2**: YSweetData container and SyncKv integration
- **Week 3**: Migration logic and integration testing
- **Week 4**: Performance testing and optimization
- **Week 5-6**: Production deployment and monitoring

## Dependencies

- `ciborium = "0.2.2"` (already available in Cargo.toml:34)
- `serde` with derive features (already available)
- `chrono` for timestamps (already available)

## Future Opportunities

1. **Rich Metadata**: Document versioning, collaborative author tracking
2. **Tool Ecosystem**: CBOR-based debugging and analysis tools
3. **Cross-Language Access**: Python/JavaScript tools for Y-Sweet data
4. **Compression**: CBOR-tagged compression for large documents
5. **Analytics**: Document usage patterns and performance metrics
6. **Backup/Export**: Human-readable document exports via CBOR tools

## Alternatives Considered

1. **Keep Bincode**: No risk but foregoes extensibility and tool integration
2. **MessagePack**: Similar benefits but less standardized than CBOR
3. **Custom Binary Format**: Full control but significant development overhead
4. **JSON**: Human readable but much larger size and slower performance
5. **Protocol Buffers**: Good performance but requires schema management

## Conclusion

Migrating to CBOR provides essential extensibility for Y-Sweet's evolution while maintaining reasonable performance characteristics. The two-layer architecture cleanly separates concerns: the extension trait handles efficient BTreeMap serialization, while SyncKv manages metadata and versioning.

The self-describing nature of CBOR maps enables external tool integration, crucial for debugging, analysis, and cross-platform access. Combined with the extensible metadata framework, this migration positions Y-Sweet for future enhancements without breaking existing deployments.

The proposed backward-compatible migration strategy minimizes deployment risk while providing a clear path toward a more maintainable and extensible data persistence layer.