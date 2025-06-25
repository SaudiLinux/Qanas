# Qanas Plugins Package
# Author: Saudi Linux (SaudiLinux1@gmail.com)

"""
Qanas Plugins System

This package contains plugins that extend the functionality of the Qanas tool.
Plugins can add new scanning capabilities, reporting features, or integration with other tools.

Plugin Structure:
- Each plugin should be a Python module or package within this directory
- Plugins should implement a standard interface (register, initialize, run)
- Plugins can be enabled/disabled in the configuration

Available Plugins:
- None yet (this is a placeholder for future plugins)
"""

__all__ = []

# Plugin registry
plugins = {}

def register_plugin(name, description, version, author, plugin_class):
    """
    Register a plugin with the Qanas plugin system
    
    Args:
        name (str): The name of the plugin
        description (str): A brief description of the plugin
        version (str): The plugin version
        author (str): The plugin author
        plugin_class: The main class of the plugin that implements the plugin interface
    """
    plugins[name] = {
        'name': name,
        'description': description,
        'version': version,
        'author': author,
        'class': plugin_class,
        'instance': None,
        'enabled': True
    }

def get_plugin(name):
    """
    Get a plugin by name
    
    Args:
        name (str): The name of the plugin
        
    Returns:
        dict: The plugin information or None if not found
    """
    return plugins.get(name)

def get_all_plugins():
    """
    Get all registered plugins
    
    Returns:
        dict: A dictionary of all registered plugins
    """
    return plugins

def enable_plugin(name):
    """
    Enable a plugin
    
    Args:
        name (str): The name of the plugin
        
    Returns:
        bool: True if the plugin was enabled, False otherwise
    """
    if name in plugins:
        plugins[name]['enabled'] = True
        return True
    return False

def disable_plugin(name):
    """
    Disable a plugin
    
    Args:
        name (str): The name of the plugin
        
    Returns:
        bool: True if the plugin was disabled, False otherwise
    """
    if name in plugins:
        plugins[name]['enabled'] = False
        return True
    return False

def initialize_plugins():
    """
    Initialize all enabled plugins
    
    Returns:
        list: A list of initialized plugin instances
    """
    initialized = []
    for name, plugin_info in plugins.items():
        if plugin_info['enabled']:
            try:
                plugin_info['instance'] = plugin_info['class']()
                plugin_info['instance'].initialize()
                initialized.append(plugin_info['instance'])
            except Exception as e:
                print(f"Error initializing plugin {name}: {str(e)}")
    return initialized

# Plugin interface class (for reference)
class PluginInterface:
    """
    Base class for Qanas plugins
    
    All plugins should inherit from this class and implement its methods
    """
    
    def __init__(self):
        self.name = "Base Plugin"
        self.description = "Base plugin class"
        self.version = "1.0.0"
        self.author = "Unknown"
    
    def initialize(self):
        """
        Initialize the plugin
        This method is called when the plugin is loaded
        """
        pass
    
    def run(self, target, options=None):
        """
        Run the plugin against a target
        
        Args:
            target (str): The target to scan
            options (dict): Additional options for the plugin
            
        Returns:
            dict: The results of the plugin run
        """
        raise NotImplementedError("Plugins must implement the run method")
    
    def cleanup(self):
        """
        Clean up any resources used by the plugin
        This method is called when the plugin is unloaded
        """
        pass