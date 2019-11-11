//
//  ViewController.m
//  iospwn_typhoonPwn_2019
//
//  Created by aa on 6/13/19.
//  Copyright © 2019 aa. All rights reserved.
//

#import "ViewController.h"
#include <sys/stat.h>

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIImageView *pwned_icon;
@property (weak, nonatomic) IBOutlet UILabel *auth_label1;
@property (weak, nonatomic) IBOutlet UILabel *auth_label2;
@property (weak, nonatomic) IBOutlet UILabel *auth_label3;

@property (weak, nonatomic) IBOutlet UITextView *log_window;

@end

@implementation ViewController

UIView *displayviews[4];
void display_win(){
    for(int i=0; i<4; i++){
        displayviews[i].alpha = 1;
    }
}

char *Build_itunes_path(char *filename){
    if(!filename)
        return strdup([[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES)[0]stringByAppendingString:@"/"] UTF8String]);
    char *path = strdup([[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES)[0]stringByAppendingPathComponent:[NSString stringWithUTF8String:filename]] UTF8String]);
    //unlink(path);
    return path;
}

char *Build_resource_path(char *filename){
    if(!filename)
        return strdup([[[[NSBundle mainBundle] resourcePath] stringByAppendingString:@"/"] UTF8String]);
    char *path = strdup([[[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:[NSString stringWithUTF8String:filename]] UTF8String]);
    return path;
}

UITextView *log_outview_toC;
void log_toView(const char *input_cstr){
    log_outview_toC.text = [log_outview_toC.text stringByAppendingString:[NSString stringWithUTF8String:input_cstr]];
}

#define printf_wow(X,X1...) {char logdata[256];snprintf(logdata, sizeof(logdata), X, X1);extern void log_toView(const char *input_cstr);log_toView(logdata);}
#define print_line(X) {extern void log_toView(const char *input_cstr);log_toView(X);}

char *reverseShell_path;
char *ios_reverseshell;

int ready = 0;

- (void)viewDidLoad {
    [super viewDidLoad];
    
    log_outview_toC = self.log_window;

    CGFloat degrees = -20.0f;
    CGFloat radians = degrees * M_PI/180;
    self.pwned_icon.transform = CGAffineTransformMakeRotation(radians);
    self.pwned_icon.alpha = 0;
    self.auth_label1.alpha = 0;
    self.auth_label2.alpha = 0;
    self.auth_label3.alpha = 0;
    
    displayviews[0] = self.pwned_icon;
    displayviews[1] = self.auth_label1;
    displayviews[2] = self.auth_label2;
    displayviews[3] = self.auth_label3;
    
    self.log_window.layer.borderColor = [UIColor colorWithRed:0.99 green:0.76 blue:0.42 alpha:1.0].CGColor;
    self.log_window.layer.borderWidth = 3;
    
    ios_reverseshell = Build_itunes_path("ios_reverseshell");
    reverseShell_path = Build_itunes_path("reverseShell");
    
    if(!access(ios_reverseshell, F_OK) && !access(reverseShell_path, F_OK))
        ready = 1;
    if(access(ios_reverseshell, F_OK)){
        print_line("ios_reverseshell not found\n");
    }
    if(access(reverseShell_path, F_OK)){
        print_line("reverseShell_path not found\n");
    }
}

- (IBAction)click_action:(id)sender {
    extern void exp_start(void);
    if(ready)
        exp_start();
}

@end
