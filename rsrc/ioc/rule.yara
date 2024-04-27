rule ExampleTestfileRule
{
    meta:                                                             
        description = "This is example file"                            

    strings:
        $text_string = "pyautogui"
        $text_binary = {54 68 69 73 20 69 73 20 61 20 74 65 73 74}

    condition:
        $text_string or $text_binary
}
