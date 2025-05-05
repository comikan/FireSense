#!/usr/bin/env python3
"""
FireSense YAML Work-Based Protocols (YAML-WBP) Processor
A professional-grade system for processing YAML-based workflow protocols with:
- Advanced YAML schema validation
- Dynamic workflow execution
- Protocol versioning and migration
- Dependency management
- Error handling and recovery
- Audit logging
"""

import os
import sys
import yaml
import json
import logging
import hashlib
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum, auto
from datetime import datetime
from pathlib import Path
import inspect
import functools
import threading
import copy
import jsonschema
from jsonschema import validate
import uuid
import tempfile
import shutil

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('yaml_wbp.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("FireSense.YAML-WBP")

class ProtocolPhase(Enum):
    INITIALIZATION = auto()
    VALIDATION = auto()
    EXECUTION = auto()
    CLEANUP = auto()
    VERIFICATION = auto()

class ExecutionStatus(Enum):
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    ROLLED_BACK = auto()

class DependencyType(Enum):
    FILE = auto()
    NETWORK = auto()
    SERVICE = auto()
    DATABASE = auto()

@dataclass
class ProtocolDependency:
    name: str
    type: DependencyType
    required: bool = True
    version: Optional[str] = None
    checksum: Optional[str] = None
    uri: Optional[str] = None

@dataclass
class ProtocolStep:
    name: str
    action: str
    parameters: Dict[str, Any]
    retries: int = 3
    timeout: int = 300
    rollback_action: Optional[str] = None
    rollback_params: Optional[Dict[str, Any]] = None
    depends_on: List[str] = field(default_factory=list)

@dataclass
class ProtocolExecution:
    execution_id: str
    protocol: 'WorkProtocol'
    start_time: datetime
    end_time: Optional[datetime] = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    current_step: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)

class WorkProtocol:
    """Main protocol class for YAML-WBP processing"""
    
    SCHEMA = {
        "type": "object",
        "properties": {
            "metadata": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "description": {"type": "string"},
                    "author": {"type": "string"},
                    "created": {"type": "string", "format": "date-time"},
                    "modified": {"type": "string", "format": "date-time"}
                },
                "required": ["name", "version"]
            },
            "dependencies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "type": {"type": "string", "enum": [dt.name for dt in DependencyType]},
                        "required": {"type": "boolean"},
                        "version": {"type": "string"},
                        "checksum": {"type": "string"},
                        "uri": {"type": "string"}
                    },
                    "required": ["name", "type"]
                }
            },
            "environment": {
                "type": "object",
                "additionalProperties": {"type": "string"}
            },
            "parameters": {
                "type": "object",
                "additionalProperties": True
            },
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "action": {"type": "string"},
                        "parameters": {"type": "object"},
                        "retries": {"type": "integer", "minimum": 0},
                        "timeout": {"type": "integer", "minimum": 1},
                        "rollback_action": {"type": "string"},
                        "rollback_params": {"type": "object"},
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["name", "action"]
                }
            },
            "hooks": {
                "type": "object",
                "properties": {
                    "pre_execution": {"type": "string"},
                    "post_execution": {"type": "string"},
                    "on_error": {"type": "string"}
                }
            }
        },
        "required": ["metadata", "steps"]
    }
    
    ACTION_REGISTRY: Dict[str, Callable] = {}
    
    def __init__(self, yaml_content: str):
        self.raw_content = yaml_content
        self.data = self._load_and_validate(yaml_content)
        self.executions: Dict[str, ProtocolExecution] = {}
        self._lock = threading.Lock()
        self._action_cache: Dict[str, Callable] = {}
        
        # Initialize from YAML data
        self.metadata = self.data.get('metadata', {})
        self.dependencies = [
            ProtocolDependency(
                name=dep.get('name'),
                type=DependencyType[dep.get('type')],
                required=dep.get('required', True),
                version=dep.get('version'),
                checksum=dep.get('checksum'),
                uri=dep.get('uri')
            ) for dep in self.data.get('dependencies', [])
        ]
        self.environment = self.data.get('environment', {})
        self.parameters = self.data.get('parameters', {})
        self.steps = [
            ProtocolStep(
                name=step.get('name'),
                action=step.get('action'),
                parameters=step.get('parameters', {}),
                retries=step.get('retries', 3),
                timeout=step.get('timeout', 300),
                rollback_action=step.get('rollback_action'),
                rollback_params=step.get('rollback_params'),
                depends_on=step.get('depends_on', [])
            ) for step in self.data.get('steps', [])
        ]
        self.hooks = self.data.get('hooks', {})
        
    @classmethod
    def register_action(cls, name: str):
        """Decorator to register protocol actions"""
        def decorator(func):
            cls.ACTION_REGISTRY[name] = func
            return func
        return decorator
    
    @classmethod
    def from_file(cls, file_path: str):
        """Create protocol from YAML file"""
        with open(file_path, 'r') as f:
            content = f.read()
        return cls(content)
    
    def _load_and_validate(self, yaml_content: str) -> Dict[str, Any]:
        """Load and validate YAML content against schema"""
        try:
            data = yaml.safe_load(yaml_content)
            validate(instance=data, schema=self.SCHEMA)
            return data
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error: {e}")
            raise ValueError(f"Invalid YAML: {e}")
        except jsonschema.ValidationError as e:
            logger.error(f"Schema validation error: {e}")
            raise ValueError(f"Schema validation failed: {e.message}")
    
    def _resolve_action(self, action_name: str) -> Callable:
        """Resolve action name to callable function"""
        if action_name in self._action_cache:
            return self._action_cache[action_name]
        
        # Check built-in actions
        if action_name in self.ACTION_REGISTRY:
            self._action_cache[action_name] = self.ACTION_REGISTRY[action_name]
            return self.ACTION_REGISTRY[action_name]
        
        # Check for module path (e.g., "module.function")
        if '.' in action_name:
            module_path, func_name = action_name.rsplit('.', 1)
            try:
                module = __import__(module_path, fromlist=[func_name])
                func = getattr(module, func_name)
                if callable(func):
                    self._action_cache[action_name] = func
                    return func
            except (ImportError, AttributeError) as e:
                logger.error(f"Failed to import action {action_name}: {e}")
        
        raise ValueError(f"Unknown action: {action_name}")
    
    def _execute_hook(self, hook_name: str, execution: ProtocolExecution):
        """Execute a protocol hook if defined"""
        if hook_name in self.hooks:
            try:
                hook_func = self._resolve_action(self.hooks[hook_name])
                hook_func(execution)
            except Exception as e:
                logger.error(f"Hook '{hook_name}' execution failed: {e}")
    
    def _verify_dependencies(self) -> bool:
        """Verify all protocol dependencies are available"""
        missing_deps = []
        for dep in self.dependencies:
            if dep.type == DependencyType.FILE:
                if not os.path.exists(dep.name):
                    if dep.required:
                        missing_deps.append(f"Missing required file: {dep.name}")
                    else:
                        logger.warning(f"Optional file not found: {dep.name}")
            
        if missing_deps:
            raise ValueError(f"Missing dependencies: {', '.join(missing_deps)}")
        return True
    
    def _execute_step(self, step: ProtocolStep, execution: ProtocolExecution) -> bool:
        """Execute a single protocol step"""
        logger.info(f"Executing step: {step.name}")
        execution.current_step = step.name
        
        try:
            action_func = self._resolve_action(step.action)
            
            # Prepare execution context
            context = {
                'parameters': copy.deepcopy(self.parameters),
                'environment': copy.deepcopy(self.environment),
                'execution_id': execution.execution_id,
                'step_name': step.name,
                'protocol': self.metadata,
                'results': copy.deepcopy(execution.results)
            }
            
            # Merge step parameters with context
            params = {**context, **step.parameters}
            
            # Execute with retries
            for attempt in range(1, step.retries + 1):
                try:
                    result = action_func(**params)
                    execution.results[step.name] = result
                    logger.info(f"Step {step.name} completed successfully")
                    return True
                except Exception as e:
                    logger.warning(f"Attempt {attempt} failed for step {step.name}: {e}")
                    if attempt == step.retries:
                        execution.errors[step.name] = str(e)
                        logger.error(f"Step {step.name} failed after {step.retries} attempts")
                        return False
                    time.sleep(1)  # Simple backoff
            
        except Exception as e:
            execution.errors[step.name] = str(e)
            logger.error(f"Step {step.name} execution failed: {e}")
            return False
    
    def _rollback_step(self, step: ProtocolStep, execution: ProtocolExecution):
        """Rollback a protocol step if rollback action is defined"""
        if step.rollback_action:
            logger.info(f"Rolling back step: {step.name}")
            try:
                rollback_func = self._resolve_action(step.rollback_action)
                
                context = {
                    'parameters': copy.deepcopy(self.parameters),
                    'environment': copy.deepcopy(self.environment),
                    'execution_id': execution.execution_id,
                    'step_name': step.name,
                    'protocol': self.metadata,
                    'results': copy.deepcopy(execution.results),
                    'error': execution.errors.get(step.name, 'Unknown error')
                }
                
                params = {**context, **(step.rollback_params or {})}
                rollback_func(**params)
                logger.info(f"Rollback for step {step.name} completed")
            except Exception as e:
                logger.error(f"Rollback for step {step.name} failed: {e}")
                raise
    
    def execute(self, execution_id: Optional[str] = None) -> ProtocolExecution:
        """Execute the protocol workflow"""
        execution_id = execution_id or str(uuid.uuid4())
        execution = ProtocolExecution(
            execution_id=execution_id,
            protocol=self,
            start_time=datetime.now()
        )
        
        with self._lock:
            self.executions[execution_id] = execution
            execution.status = ExecutionStatus.RUNNING
            
            try:
                # Phase 1: Initialization
                self._execute_hook('pre_execution', execution)
                
                # Phase 2: Validation
                self._verify_dependencies()
                
                # Phase 3: Execution
                for step in self.steps:
                    # Check dependencies
                    if any(dep not in execution.results for dep in step.depends_on):
                        missing = [dep for dep in step.depends_on if dep not in execution.results]
                        raise ValueError(f"Step {step.name} missing dependencies: {missing}")
                    
                    success = self._execute_step(step, execution)
                    if not success:
                        execution.status = ExecutionStatus.FAILED
                        self._execute_hook('on_error', execution)
                        return execution
                
                # Phase 4: Verification
                execution.status = ExecutionStatus.COMPLETED
                execution.end_time = datetime.now()
                self._execute_hook('post_execution', execution)
                
            except Exception as e:
                execution.status = ExecutionStatus.FAILED
                execution.errors['protocol'] = str(e)
                logger.error(f"Protocol execution failed: {e}")
                
                # Attempt rollback for completed steps
                try:
                    for step in reversed(self.steps):
                        if step.name in execution.results:
                            self._rollback_step(step, execution)
                    execution.status = ExecutionStatus.ROLLED_BACK
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")
                
                self._execute_hook('on_error', execution)
            
            return execution
    
    def get_execution(self, execution_id: str) -> Optional[ProtocolExecution]:
        """Get execution by ID"""
        return self.executions.get(execution_id)
    
    def get_execution_status(self, execution_id: str) -> Optional[ExecutionStatus]:
        """Get execution status"""
        if execution := self.executions.get(execution_id):
            return execution.status
        return None
    
    def get_execution_report(self, execution_id: str) -> Dict[str, Any]:
        """Generate an execution report"""
        if execution := self.executions.get(execution_id):
            return {
                'execution_id': execution.execution_id,
                'protocol': self.metadata['name'],
                'version': self.metadata['version'],
                'status': execution.status.name,
                'start_time': execution.start_time.isoformat(),
                'end_time': execution.end_time.isoformat() if execution.end_time else None,
                'duration': (execution.end_time - execution.start_time).total_seconds() if execution.end_time else None,
                'current_step': execution.current_step,
                'success_steps': list(execution.results.keys()),
                'failed_steps': list(execution.errors.keys()),
                'errors': execution.errors
            }
        return {}

# Example Protocol Actions
@WorkProtocol.register_action('file.copy')
def file_copy(source: str, destination: str, **kwargs) -> Dict[str, Any]:
    """Copy file action"""
    try:
        shutil.copy2(source, destination)
        return {
            'status': 'success',
            'source': source,
            'destination': destination,
            'checksum': _calculate_file_checksum(destination)
        }
    except Exception as e:
        raise ValueError(f"File copy failed: {e}")

@WorkProtocol.register_action('file.delete')
def file_delete(path: str, **kwargs) -> Dict[str, Any]:
    """Delete file action"""
    try:
        if not os.path.exists(path):
            return {'status': 'skipped', 'reason': 'File does not exist'}
        
        os.remove(path)
        return {'status': 'success', 'path': path}
    except Exception as e:
        raise ValueError(f"File deletion failed: {e}")

def _calculate_file_checksum(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate file checksum"""
    hash_func = hashlib.new(algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

if __name__ == "__main__":
    example_protocol = """
    metadata:
      name: "file_processing"
      version: "1.0"
      description: "Process and validate incoming files"
      author: "FireSense Team"
    
    dependencies:
      - name: "/input/files"
        type: "FILE"
        required: true
    
    parameters:
      output_dir: "/processed/files"
    
    steps:
      - name: "validate_input"
        action: "file.copy"
        parameters:
          source: "/input/files/source.dat"
          destination: "{{ parameters.output_dir }}/source.dat"
        rollback_action: "file.delete"
        rollback_params:
          path: "{{ parameters.output_dir }}/source.dat"
    
      - name: "create_backup"
        action: "file.copy"
        parameters:
          source: "{{ parameters.output_dir }}/source.dat"
          destination: "{{ parameters.output_dir }}/backup/source.bak"
    """
    
    try:
        # Load and execute protocol
        protocol = WorkProtocol(example_protocol)
        execution = protocol.execute()
        
        # Print execution report
        print(json.dumps(protocol.get_execution_report(execution.execution_id), indent=2))
        
    except Exception as e:
        logger.error(f"Protocol execution failed: {e}")
        sys.exit(1)
