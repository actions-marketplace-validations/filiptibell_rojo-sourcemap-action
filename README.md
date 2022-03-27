# Rojo sourcemap action

This action creates a JSON sourcemap file from a Rojo project.

## Inputs

* `output-path` - **Required** - The path where the source map file should be created.
* `project-path` - **Required** - The path to the Rojo project file.
* `prettify` - **Optional** - If the created JSON file should be in pretty format or not.

## Outputs

* `success` If source map creation was successful or not. Either `true` or `false`.
* `message` An error message if source map creation was not successful, or `"Success!"` if successful.

## Example usage

```yaml
uses: filiptibell/rojo-sourcemap-action@v1.3
with:
  output-path: 'bin/SourceMap.json'
  project-path: 'default.project.json'
  prettify: true
```
