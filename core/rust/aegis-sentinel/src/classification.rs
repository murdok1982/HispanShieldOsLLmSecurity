#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum ClassificationLevel {
    Unclassified = 0,
    Confidential = 1, 
    Secret = 2,
    TopSecret = 3,
}

#[derive(PartialEq)]
pub enum DataOperation {
    Read,
    Write,
}

pub enum ClassificationError {
    ReadUpViolation,
    WriteDownViolation,
}

pub fn enforce_data_flow(
    source_level: ClassificationLevel,
    target_level: ClassificationLevel,
    operation: DataOperation
) -> Result<(), ClassificationError> {
    // Implementar Bell-LaPadula: no read-up, no write-down
    if operation == DataOperation::Read && source_level > target_level {
        return Err(ClassificationError::ReadUpViolation);
    }
    if operation == DataOperation::Write && source_level < target_level {
        return Err(ClassificationError::WriteDownViolation);
    }
    // Loguear intento en audit chain
    Ok(())
}
