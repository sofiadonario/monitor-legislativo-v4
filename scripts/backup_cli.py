#!/usr/bin/env python3
"""
Backup CLI Tool
Command-line interface for backup management
"""

import sys
import os
import argparse
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.utils.backup_manager import BackupManager, BackupConfig

def create_backup(args):
    """Create a new backup"""
    config = BackupConfig(
        backup_dir=args.backup_dir,
        retention_days=args.retention_days,
        compression=not args.no_compression,
        include_logs=args.include_logs,
        include_cache=args.include_cache
    )
    
    manager = BackupManager(config)
    
    try:
        metadata = manager.create_backup(args.type)
        
        print(f"✅ Backup created successfully!")
        print(f"Backup ID: {metadata.backup_id}")
        print(f"Size: {metadata.size_bytes / (1024*1024):.2f} MB")
        print(f"Duration: {metadata.duration_seconds:.2f} seconds")
        print(f"Files: {metadata.files_count}")
        
        if config.compression:
            print(f"Compression ratio: {metadata.compression_ratio:.2f}x")
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        sys.exit(1)

def list_backups(args):
    """List all backups"""
    config = BackupConfig(backup_dir=args.backup_dir)
    manager = BackupManager(config)
    
    backups = manager.list_backups()
    
    if not backups:
        print("No backups found.")
        return
    
    print(f"{'Backup ID':<30} {'Type':<12} {'Status':<8} {'Size (MB)':<10} {'Date':<20}")
    print("-" * 90)
    
    for backup in backups:
        size_mb = backup.size_bytes / (1024 * 1024)
        date_str = backup.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        status_icon = "✅" if backup.status == "success" else "❌"
        
        print(f"{backup.backup_id:<30} {backup.backup_type:<12} {status_icon:<8} {size_mb:<10.2f} {date_str:<20}")

def restore_backup(args):
    """Restore from backup"""
    config = BackupConfig(backup_dir=args.backup_dir)
    manager = BackupManager(config)
    
    success = manager.restore_backup(args.backup_id, args.restore_path)
    
    if success:
        print(f"✅ Backup {args.backup_id} restored successfully!")
        if args.restore_path:
            print(f"Restored to: {args.restore_path}")
    else:
        print(f"❌ Failed to restore backup {args.backup_id}")
        sys.exit(1)

def show_stats(args):
    """Show backup statistics"""
    config = BackupConfig(backup_dir=args.backup_dir)
    manager = BackupManager(config)
    
    stats = manager.get_stats()
    
    print("📊 Backup Statistics")
    print("=" * 30)
    print(f"Total backups: {stats['total_backups']}")
    print(f"Total size: {stats['total_size_mb']:.2f} MB")
    print(f"Success rate: {stats['success_rate']:.1f}%")
    print(f"Retention period: {stats['retention_days']} days")
    print(f"Scheduler status: {'Running' if stats['scheduler_running'] else 'Stopped'}")
    
    if stats['latest_backup']:
        print(f"Latest backup: {stats['latest_backup']}")

def start_scheduler(args):
    """Start backup scheduler"""
    config = BackupConfig(
        backup_dir=args.backup_dir,
        schedule_interval=args.interval,
        schedule_time=args.time,
        retention_days=args.retention_days
    )
    
    manager = BackupManager(config)
    
    try:
        manager.start_scheduler()
        print(f"✅ Backup scheduler started ({args.interval} at {args.time})")
        print("Press Ctrl+C to stop...")
        
        # Keep running
        import time
        while True:
            time.sleep(60)
            
    except KeyboardInterrupt:
        manager.stop_scheduler()
        print("\n🛑 Backup scheduler stopped")

def cleanup_old_backups(args):
    """Clean up old backups"""
    config = BackupConfig(
        backup_dir=args.backup_dir,
        retention_days=args.days
    )
    
    manager = BackupManager(config)
    
    # Get backup count before cleanup
    backups_before = len(manager.list_backups())
    
    # Force cleanup
    manager._cleanup_old_backups()
    
    # Get backup count after cleanup
    backups_after = len(manager.list_backups())
    
    removed_count = backups_before - backups_after
    
    print(f"✅ Cleanup completed!")
    print(f"Removed {removed_count} old backups")
    print(f"Remaining backups: {backups_after}")

def verify_backup(args):
    """Verify backup integrity"""
    config = BackupConfig(backup_dir=args.backup_dir)
    manager = BackupManager(config)
    
    # Find backup
    backup_file = Path(config.backup_dir) / f"{args.backup_id}.tar.gz"
    if not backup_file.exists():
        backup_file = Path(config.backup_dir) / args.backup_id
        if not backup_file.exists():
            print(f"❌ Backup {args.backup_id} not found")
            sys.exit(1)
    
    # Load metadata
    metadata_file = Path(config.backup_dir) / f"{args.backup_id}_metadata.json"
    if not metadata_file.exists():
        print(f"❌ Metadata for backup {args.backup_id} not found")
        sys.exit(1)
    
    with open(metadata_file, 'r') as f:
        metadata = json.load(f)
    
    # Verify checksum
    current_checksum = manager._calculate_checksum(backup_file)
    stored_checksum = metadata.get('checksum', '')
    
    if current_checksum == stored_checksum:
        print(f"✅ Backup {args.backup_id} integrity verified")
        print(f"Checksum: {current_checksum}")
    else:
        print(f"❌ Backup {args.backup_id} integrity check failed!")
        print(f"Expected: {stored_checksum}")
        print(f"Actual: {current_checksum}")
        sys.exit(1)

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="Legislative Monitor Backup CLI")
    parser.add_argument('--backup-dir', default='data/backups', help='Backup directory')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create backup command
    create_parser = subparsers.add_parser('create', help='Create a new backup')
    create_parser.add_argument('--type', choices=['full', 'data', 'logs', 'incremental'], 
                              default='full', help='Backup type')
    create_parser.add_argument('--retention-days', type=int, default=30, 
                              help='Retention period in days')
    create_parser.add_argument('--no-compression', action='store_true', 
                              help='Disable compression')
    create_parser.add_argument('--include-logs', action='store_true', 
                              help='Include log files')
    create_parser.add_argument('--include-cache', action='store_true', 
                              help='Include cache data')
    create_parser.set_defaults(func=create_backup)
    
    # List backups command
    list_parser = subparsers.add_parser('list', help='List all backups')
    list_parser.set_defaults(func=list_backups)
    
    # Restore backup command
    restore_parser = subparsers.add_parser('restore', help='Restore from backup')
    restore_parser.add_argument('backup_id', help='Backup ID to restore')
    restore_parser.add_argument('--restore-path', help='Path to restore to')
    restore_parser.set_defaults(func=restore_backup)
    
    # Show stats command
    stats_parser = subparsers.add_parser('stats', help='Show backup statistics')
    stats_parser.set_defaults(func=show_stats)
    
    # Start scheduler command
    scheduler_parser = subparsers.add_parser('scheduler', help='Start backup scheduler')
    scheduler_parser.add_argument('--interval', choices=['daily', 'hourly', 'weekly'], 
                                 default='daily', help='Backup interval')
    scheduler_parser.add_argument('--time', default='02:00', help='Backup time (HH:MM)')
    scheduler_parser.add_argument('--retention-days', type=int, default=30, 
                                 help='Retention period in days')
    scheduler_parser.set_defaults(func=start_scheduler)
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old backups')
    cleanup_parser.add_argument('--days', type=int, default=30, 
                               help='Remove backups older than N days')
    cleanup_parser.set_defaults(func=cleanup_old_backups)
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify backup integrity')
    verify_parser.add_argument('backup_id', help='Backup ID to verify')
    verify_parser.set_defaults(func=verify_backup)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    args.func(args)

if __name__ == '__main__':
    main()