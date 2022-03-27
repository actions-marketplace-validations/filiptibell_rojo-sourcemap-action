const core = require('@actions/core');
const axios = require('axios');
const fs = require('fs');

const HTMLParser = require('node-html-parser');

const findProcess = require('find-process');

const { spawn } = require('child_process');

require('dotenv').config();





const ALLOWED_CLASS_NAMES = new Set([
	// Root
	'DataModel',
	// Services
	'Workspace',
	'ReplicatedFirst',
	'ReplicatedStorage',
	'ServerScriptService',
	'ServerStorage',
	'StarterGui',
	'StarterPack',
	'StarterPlayer',
	'Chat',
	// Containers
	'Folder',
	'Configuration',
	'StarterPlayerScripts',
	'StarterCharacterScripts',
])

const SCRIPT_CLASS_NAMES = new Set([
	'Script',
	'LocalScript',
	'ModuleScript',
])





const fail = (statusCode, message) => {
	return {
		success: false,
		message,
		statusCode,
		result: undefined,
	}
}

const toBool = (str) => {
	if (str.toLowerCase() === 'true') {
		return true
	}
	return false
}

const getConfig = () => {
	if (process.env.GITHUB_ACTIONS) {
		return {
			workDir: process.cwd(),
			fromGHA: true,
			outputPath: core.getInput('output-path', { required: true }),
			projectPath: core.getInput('project-path', { required: true }),
			prettify: !!core.getBooleanInput('prettify'),
		}
	} else {
		return {
			workDir: process.cwd(),
			fromGHA: false,
			outputPath: process.env.OUTPUT_PATH,
			projectPath: process.env.PROJECT_FILE,
			prettify: toBool(process.env.PRETTIFY),
		}
	}
}

const ensureDirExists = async (path) => {
	const pathNoFile = path.substring(0, path.lastIndexOf("/"));
	await fs.promises.mkdir(pathNoFile, { recursive: true });
}

const pathExists = (path) => {
	try {
		if (fs.existsSync(path)) {
			return true;
		}
	} catch {
		
	}
	return false;
}

const pathIsFile = (path) => {
	try {
		if (fs.lstatSync(path).isFile()) {
			return true;
		}
	} catch {
		
	}
	return false;
}

const cleanupPath = (path, root) => {
	// Remove working directory so that we get a
	// path relative to the root of the repository
	if (root && path.startsWith(root)) {
		path = path.slice(root.length);
		if (path.startsWith('/')) {
			path = path.slice(1);
		}
	}
	// Replace all parts in path where we backtrack
	// This pattern consists of "(non-slash-stuff)/../"
	const BACKTRACK = /([^\/]+)\/\.\.\//gi
	path = path.replace(BACKTRACK, '')
	// Return result
	return path;
}





let guidCount = 0;

/**
 * @param {HTMLParser.HTMLElement} element
 */
const buildSourceMapNode = (config, element, parent) => {
	// Create resulting root node
	const result = {
		name: '???',
		className: 'Instance',
		relevantPaths: [],
		children: [],
	}
	// Find instance name, and possibly class name, with
	// the class name defaulting to the instance name itself
	const nameLabel = element.querySelector('label.instance-title');
	if (nameLabel) {
		const nameString = nameLabel?.firstChild?.innerText;
		if (nameString) {
			result.name = nameString;
		}
		// Find instance class name, this only exists sometimes,
		// depending on if the instance was created as its own file
		// with a file name different from the class name or not
		const classLabel = nameLabel.querySelector('span');
		if (classLabel) {
			const classString = classLabel?.firstChild?.innerText;
			if (classString) {
				result.className = classString.trim().slice(1, classString.length - 2);
			} else {
				result.className = result.name;
			}
		} else {
			result.className = result.name;
		}
	}
	// If we didn't get an allowed class name or script class,
	// then we should skip processing this node any further
	if (
		!ALLOWED_CLASS_NAMES.has(result.className) &&
		!SCRIPT_CLASS_NAMES.has(result.className)
	) {
		return null;
	}
	// Find instance metadata containing relevant file paths
	// NOTE: We only do this for scripts to avoid extra processing,
	// we are creating a * source map * after all, and not
	// some kind of generic instance - to - file map
	if (SCRIPT_CLASS_NAMES.has(result.className)) {
		const metadataDiv = element.querySelector('div.instance-metadata');
		if (metadataDiv) {
			const metadataPaths = metadataDiv.querySelector('ul.path-list');
			if (metadataPaths) {
				const metadataPathListItems = metadataPaths.querySelectorAll('li')
				for (const listItem of metadataPathListItems.values()) {
					let listItemText = listItem?.firstChild?.innerText;
					if (listItemText) {
						// Make sure that the path exists and that it is a file
						if (!pathExists(listItemText)) { continue; }
						if (!pathIsFile(listItemText)) { continue; }
						// Insert cleaned up path into relevant paths
						const cleanPath = cleanupPath(listItemText, config.workDir);
						result.relevantPaths.push(cleanPath);
					}
				}
			}
		}
	}
	// Go through all instance children and create
	// nodes for them too, inserting them into this
	const childrenDiv = element.querySelector('div.instance-children');
	if (childrenDiv) {
		// NOTE: We don't use querySelectorAll directly since we would
		// then be getting descendants and not only direct children,
		// we need to first set a unique id on the children container
		// and then use that to only select the direct children of it
		guidCount += 1;
		const guid = `bsmnid${guidCount}`;
		childrenDiv.setAttribute('id', guid);
		const childDivs = element.querySelectorAll(`#${guid} > div.instance`);
		for (const childDiv of childDivs.values()) {
			buildSourceMapNode(config, childDiv, result);
		}
		childrenDiv.removeAttribute('id');
	}
	// Parent the node if any parent was given
	if (parent) {
		parent.children.push(result);
	}
	// Return resulting completed node
	return result;
}






const recurseSourceMapNode = (node, callback) => {
	if (node.children) {
		for (const child of node.children.values()) {
			recurseSourceMapNode(child, callback)
		}
	}
	callback(node)
}

const shouldKeepSourceMapNode = (node) => {
	if (!SCRIPT_CLASS_NAMES.has(node.className)) {
		if (node.children.length === 0) {
			if (node.relevantPaths.length === 0) {
				return false;
			}
		}
	}
	return true;
}

const finalizeSourceMapRootNode = (rootNode) => {
	// Cleanup nodes that don't have any children or paths
	recurseSourceMapNode(rootNode, (node) => {
		node.children = node.children.filter(child => {
			return shouldKeepSourceMapNode(child);
		});
	});
	// Create flat list of node objects for further processing
	const flatNodeList = [];
	recurseSourceMapNode(rootNode, (node) => {
		flatNodeList.push(node);
	});
	// Remove children or paths if they are empty
	for (const node of flatNodeList.values()) {
		if (node.children.length === 0) {
			delete node.children;
		}
		if (node.relevantPaths.length === 0) {
			delete node.relevantPaths;
		}
	}
}





const createSourceMap = (config) => {
	console.log('Connecting...')
	return new Promise((resolve, reject) => {
		let rojoStarted = false;
		let rojoError = '';
		// Spawn new rojo serve process with the project file
		// Why do we need to do this :( why can Rojo not just export
		// this data somewhere in the cli... it already exists... oh well
		const rojo = spawn('rojo', ['serve', config.projectPath]);
		// Create process killing helper function
		const trykill = (signal) => {
			// First, try killing the "official" way
			rojo.kill(signal);
			// Second, find rojo pid by port and kill it manually
			findProcess('port', 34872).then(list => {
				for (const proc of list.values()) {
					try {
						process.kill(proc.pid, signal);
					} catch {
						
					}
				}
			});
		}
		// Create superkill helper function
		const superkill = () => {
			setTimeout(() => { trykill('SIGTERM') }, 0);
			setTimeout(() => { trykill('SIGHUP')  }, 50);
			setTimeout(() => { trykill('SIGINT')  }, 100);
		}
		// Check for output saying the server
		// is listening and also if it errors
		rojo.stdout.on('data', (data) => {
			if (data.toString().startsWith('Rojo server listening')) {
				rojoStarted = true;
			}
		});
		rojo.stderr.on('data', (data) => {
			rojoError = data.toString();
		});
		// Check for output or error every 100ms
		let intervalId = null;
		intervalId = setInterval(async () => {
			// Check if we got a status yet
			if (!rojoStarted && !rojoError) {
				return;
			}
			// Check to make sure we did not enter the interval
			// callback if we had already finished before (???)
			if (!intervalId) {
				return;
			}
			// We got a status, clear the loop
			clearInterval(intervalId);
			intervalId = null;
			// Check if rojo started up successfully
			if (rojoStarted) {
				// Fetch page that contains relevant paths
				axios.default({
					method: 'GET',
					url: 'http://localhost:34872/show-instances',
				}).then(data => {
					// Kill rojo now that we no longer need it
					superkill();
					// Emit processing message
					console.log('')
					console.log("Processing...")
					// Parse html after body, ignore all the head and styling stuff
					const fullPage = data.data;
					const bodyIdx = fullPage.indexOf('<body>');
					const htmlNoHead = HTMLParser.parse('<html>' + fullPage.slice(bodyIdx));
					// Find the root instance element (this is the datamodel)
					const rootInstance = htmlNoHead.querySelector('html body div.root main.main div.instance');
					// Create the full tree starting at the root instance, then do some extra cleanup
					const rootNode = buildSourceMapNode(config, rootInstance, null);
					finalizeSourceMapRootNode(rootNode);
					// Resolve with tree result
					resolve({
						success: true,
						message: 'OK',
						statusCode: 0,
						result: rootNode
					});
				}).catch(err => {
					reject(err);
				});
			} else if (rojoError) {
				// Kill rojo
				superkill();
				// Reject with the error message
				reject(rojoError);
			}
		}, 100);
	});
}





const run = async (config) => {
	// Empty line first to make things look nice
	console.log('')
	// Perform task
	const result = await createSourceMap(config);
	if (!result.success) {
		return fail(
			result.statusCode,
			result.message
		)
	}
	// Stringify result for writing to file
	console.log('')
	console.log('Serializing...')
	const spacing = config.prettify ? '\t' : null
	const output = JSON.stringify(result.result, null, spacing);
	console.log('')
	// Make sure the directories for the
	// output path exists, otherwise create
	if (config.outputPath.indexOf('/') !== -1) {
		console.log('Writing directory...')
		await ensureDirExists(config.outputPath);
	}
	// Write the serialized json file to disk
	console.log('Writing file...')
	await fs.promises.writeFile(config.outputPath, output);
	// Done!
	return {
		success: true,
		message: 'OK',
		statusCode: 0,
		result: null,
	}
}





const config = getConfig()

run(config).then(res => {
	if (res.success) {
		if (config.fromGHA) {
			core.setOutput('success', 'true')
			core.setOutput('message', 'Success!')
		} else {
			console.log('')
			console.log('Sourcemap created successfully!')
		}
	} else {
		if (config.fromGHA) {
			core.setOutput('success', 'false')
			core.setOutput('message', res.message)
			core.setFailed(res.message)
		} else {
			console.log('')
			console.log(res.message)
		}
	}
}).catch(err => {
	if (config.fromGHA) {
		core.setOutput('success', 'false')
		core.setOutput('message', err)
		core.setFailed(err)
	} else {
		console.log('')
		console.error(err)
	}
})