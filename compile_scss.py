import sass
import os

def compile_scss():
    scss_dir = 'static/scss'
    css_dir = 'static/css'
    
    if not os.path.exists(css_dir):
        os.makedirs(css_dir)
    
    main_scss = os.path.join(scss_dir, 'main.scss')
    main_css = os.path.join(css_dir, 'main.css')
    main_map = os.path.join(css_dir, 'main.css.map')
    
    print(f"Compiling {main_scss} to {main_css} (with Source Maps)...")
    
    # Using source_comments=True can also help for simple inspection
    # source_map_filename generates the .map file for modern browsers
    compiled_css, source_map = sass.compile(
        filename=main_scss, 
        output_style='expanded',
        source_map_filename=main_map,
        source_comments=True
    )
    
    # Save CSS
    with open(main_css, 'w') as f:
        f.write(compiled_css)
        
    # Save Map
    with open(main_map, 'w') as f:
        f.write(source_map)
        
    print("Done compiling main.scss and source map.")

if __name__ == '__main__':
    compile_scss()
