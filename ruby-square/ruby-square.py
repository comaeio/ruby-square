#!/usr/bin/env python3
"""
 Ruby Square is a utility for Azure Sphere.

 Date: June-2020

 Authors:
 - Matt Suiche (msuiche)
 - Nikita Karetnikov (nkaretnikov)
"""

import argparse
from asxipfs import *
from imagemanifest import *

from os import listdir
from os.path import isfile, join

def get_application_name(input_file):
    app_file = asxipfs()
    app_file.open_file(input_file)
    application_name = app_file.get_application_name()
    app_file.close_file()

    return application_name.replace(' ', '-').lower().replace('\0', '')

def unpack_image(input_file, output=None):
    azfs = asxipfs()
    azfs.open_file(input_file)
    if output:
        print("Unpacking image...")
        azfs.unpack(output)
    else:
        azfs.print_nodes()
    azfs.close_file()


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Ruby Square for Azure Sphere.")
    argparser.add_argument("-g", "--godmode", action="store_true", help="Process a recovery folder")
    argparser.add_argument("-u", "--unpack", action="store_true", help="Unpack an Azure ROMFS image")
    argparser.add_argument("-p", "--pack", action="store_true", help="Pack an Azure ROMFS image")
    argparser.add_argument("-i", "--input", "--input", help="Input file/directory")
    argparser.add_argument("-o", "--output", "--output", help="Output file/directory")
    args = argparser.parse_args()

    if not args.unpack and not args.pack and not args.godmode:
        argparser.print_help()
        exit(1)

    if args.unpack and not args.input:
        argparser.print_help()
        exit(1)

    if args.godmode and not args.input:
        argparser.print_help()
        exit(1)

    if args.pack and not args.output:
        argparser.print_help()
        exit(1)

    azfs = asxipfs()

    if args.godmode:
        recovery_file_path = join(os.path.dirname(args.input), 'recovery.imagemanifest')
        imgmanifest = imagemanifest()
        imgmanifest.open_file(recovery_file_path)

        onlyfiles = [f for f in listdir(args.input) if isfile(join(args.input, f))]
        images = [f for f in onlyfiles if f.endswith(".bin")]

        for image in images:
            input_file = join(os.path.dirname(args.input), image)
            print("%s:" % input_file)

            dst_dir = imgmanifest.get_folder_name(image) + "_" + get_application_name(input_file)
            dst_file = dst_dir + '_' + '.bin'
            print(dst_file)

            renamed_file = join(os.path.dirname(args.input), dst_file)
            
            os.rename(input_file, renamed_file)

            output_dir = join(os.path.dirname(args.input), dst_dir)
            print("%s -> %s -> %s" % (input_file, renamed_file, output_dir))
            unpack_image(renamed_file, output_dir)

        imgmanifest.print()
        imgmanifest.close_file()
    else:
        if args.unpack:   
            unpack_image(args.input, args.output)
        elif args.pack:
            azfs = asxipfs()
            print("Packing image...")
            print("Input directory: %s\n"
                "Output file:     %s" % (os.path.dirname(args.input), args.output))
            azfs.pack(args.input, args.output)
