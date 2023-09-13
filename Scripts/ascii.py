import pyfiglet

def generate_ascii_art(text, font="standard"):
    try:
        ascii_art = pyfiglet.figlet_format(text, font=font)
        return ascii_art
    except Exception as e:
        return f"An error occurred: {e}"

def list_available_fonts():
    fonts = pyfiglet.FigletFont.getFonts()
    print("Available fonts:")
    for i, font in enumerate(fonts, start=1):
        print(f"{i}. {font}")
    print("")

def export_to_file(filename, ascii_art):
    try:
        with open(filename, "w") as file:
            file.write(ascii_art)
        print(f"ASCII art saved to {filename}")
    except Exception as e:
        print(f"An error occurred while saving to {filename}: {e}")

if __name__ == "__main__":
    list_available_fonts()
    
    while True:
        try:
            font_choice = int(input("Choose a font number (or press Enter for the default 'standard' font): ").strip())
            break
        except ValueError:
            print("Invalid input. Please enter a valid font number.")

    if 1 <= font_choice <= len(pyfiglet.FigletFont.getFonts()):
        selected_font = pyfiglet.FigletFont.getFonts()[font_choice - 1]
    else:
        selected_font = "standard"

    input_text = input("Enter the text to convert to ASCII art: ")
    
    result = generate_ascii_art(input_text, selected_font)
    
    print(result)
    
    export_choice = input("Do you want to export the ASCII art to a text file? (yes/no): ").strip().lower()
    
    if export_choice == "yes":
        filename = input("Enter the filename (e.g., output.txt): ").strip()
        export_to_file(filename, result)

