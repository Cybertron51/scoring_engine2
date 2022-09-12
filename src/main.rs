// this sucks

use std::fs::File;
use std::fs;
use std::io::prelude::*;
use std::{thread, time};
use std::process::Command;

pub fn listprocs() { // list processes (ps aux)
    Command::new("ps")
            .arg("-a")
            .arg("-u")
            .arg("-x")
            .spawn()
            .expect("ps -aux failed to start");
}

pub fn firewall() { // firewall status (ufw status verbose)
    Command::new("ufw")
        .arg("status")
        .arg("verbose")
        .spawn()
        .expect("ufw failed to start");
}

pub fn fakefilecheck(fakefile: &str) { // used to confuse lsof or other tools, makes engine harder to crack
    let mut f = File::open(fakefile).expect("file not found");
}

pub fn filecheck(query: &str, contents: &str) -> bool { // check if query is in a file

    let mut infile = false;
    if contents.contains(query) {
        infile = true;
    }

    return infile;

}

pub fn confuser_defaultlist() {
    fakefilecheck("/etc/passwd");
    fakefilecheck("/etc/shadow");
    fakefilecheck("/etc/group");
    fakefilecheck("/etc/sudoers"); 
}

pub struct Vuln {
    points: u64, // how many points its worth
    comment: String, // what appears on the scoring report
    filetocheck: String, // the filepath that the config will be in
    answer: String, // what keyword the vuln has (ex: deleting 
    solved: bool, // has it been fixed
}

impl Vuln {
    pub fn filereturn(&self) -> String { // function to read a config file
	let mut f = File::open(&self.filetocheck).expect("file not found");
        let mut readable = String::new();
        f.read_to_string(&mut readable).unwrap();
	return readable;
        }   
    
    pub fn check_solved(&mut self) -> bool { // check if a vuln has been fixed or no
	let patched = filecheck(&self.answer, &self.filereturn());
	if patched == true {
	    self.solved = true;
        }
	else {
	    self.solved = false;
	    }	
	return patched;
    }    
}	   

pub fn config_vuln(points: u64, comment: String, filetocheck: String, answer: String) -> Vuln { // word in file
    Vuln {
        points: points,
        comment: comment,
	filetocheck: filetocheck,
        answer: answer,
	solved: false,
    }
}	

pub fn package_vuln(points: u64, comment: String, answer: String) -> Vuln { // for checking for package
    Vuln {
        points: points,
        comment: comment,
        filetocheck: "/var/lib/dpkg/status".to_string(),
        answer: (["Package: ", &answer].concat()),
        solved: false,
    }
}

pub fn scoring(mut vulns: Vec<Vuln>, start: time::Instant) {
        loop {
    let mut scoring_report = String::new();
        let mut scored_points = 0;
        let mut possible_points = 0;
    let duration = start.elapsed();
    scoring_report.push_str(&format!("Time elapsed: {:?}", duration));
        scoring_report.push_str("\n");
        for items in vulns.iter_mut() {
        possible_points = possible_points + &items.points;
        items.check_solved();
        if items.filetocheck == "/var/lib/dpkg/status" {
        items.solved = !items.solved
        }
        if items.solved == true {
        scored_points = scored_points + &items.points;
            scoring_report.push_str(&items.points.to_string());
        scoring_report.push_str(" points - ");
        scoring_report.push_str(&items.comment);
        scoring_report.push_str("\n");
        }

            }
        // write will create the file if it doesnt exist
        fs::write("/home/derek/Desktop/scoringreport.txt", &scoring_report).expect("can't read scoring report file lol"); // writing to the scoring report
        thread::sleep(time::Duration::from_millis(30000)); // loop runs every 30 seconds
    }
}


fn main() {
    
    let mut vulns: Vec<Vuln> = Vec::new();    // vector of Vuln structs
    // example vulns
    vulns.push(config_vuln(4, "solved this vuln".to_string(), "/etc/passwd".to_string(), "user1".to_string()));
    vulns.push(package_vuln(4, "package found".to_string(), "telnet".to_string()));
    vulns.push(config_vuln(6, "host.conf configured good".to_string(), "/etc/host.conf".to_string(), "multi on".to_string()));
    // put vulns here as vulns.push(<config_vuln or package_vuln>(points, description, the file the vuln is in, the keyword));
    // please append .to_string() to any strings in the arguments or it will break :(
    let start = time::Instant::now();    // start time
    listprocs();
    firewall();
	scoring(vulns, start);	
}
