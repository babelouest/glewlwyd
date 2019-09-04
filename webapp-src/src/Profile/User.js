import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class User extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      pattern: props.pattern,
      profile: props.profile,
      listAddValue: this.initListAdd(props.pattern),
      listEltConfirm: this.initListConfirm(props.pattern),
      listError: {}
    };
    
    this.editElt = this.editElt.bind(this);
    this.createData = this.createData.bind(this);
    this.initListAdd = this.initListAdd.bind(this);
    this.initListConfirm = this.initListConfirm.bind(this);
    this.deleteListElt = this.deleteListElt.bind(this);
    this.changeElt = this.changeElt.bind(this);
    this.toggleBooleanElt = this.toggleBooleanElt.bind(this);
    this.changeListAddElt = this.changeListAddElt.bind(this);
    this.AddListElt = this.AddListElt.bind(this);
    this.changeEltConfirm = this.changeEltConfirm.bind(this);
    this.changeTextArea = this.changeTextArea.bind(this);
    this.uploadFile = this.uploadFile.bind(this);
    this.editElt = this.editElt.bind(this);
    this.saveProfile = this.saveProfile.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      pattern: nextProps.pattern,
      profile: nextProps.profile,
      listAddValue: this.initListAdd(nextProps.pattern),
      listEltConfirm: this.initListConfirm(nextProps.pattern),
      listError: {}
    });
  }
  
  createData() {
    var data = {};
    this.state.pattern.forEach((pat, index) => {
      if (pat.list) {
        data[pat.name] = [];
      } else if (pat.defaultValue) {
        data[pat.name] = pat.defaultValue;
      } else {
        data[pat.name] = "";
      }
    });
    this.setState({data: data});
  }

  initListAdd(patternList) {
    var listAddValue = {};
    if (patternList) {
      patternList.forEach((pat) => {
        if (pat.list) {
          listAddValue[pat.name] = "";
        }
      });
    }
    return listAddValue;
  }

  initListConfirm(patternList) {
    var listEltConfirm = {};
    if (patternList) {
      patternList.forEach((pat) => {
        if (pat.confirm) {
          listEltConfirm[pat.name] = "";
        }
      });
    }
    return listEltConfirm;
  }

  deleteListElt(e, name, index) {
    var profile = this.state.profile;
    if (profile[name]) {
      profile[name].splice(index, 1);
      this.setState({profile: profile});
    }
  }

  changeElt(e, name) {
    var profile = this.state.profile;
    profile[name] = e.target.value;
    this.setState({profile: profile});
  }

  toggleBooleanElt(e, name) {
    var profile = this.state.profile;
    profile[name] = !profile[name];
    this.setState({profile: profile});
  }

  changeListAddElt(e, name) {
    var listAddValue = this.state.listAddValue;
    listAddValue[name] = e.target.value;
    this.setState({listAddValue: listAddValue});
  }

  AddListElt(e, name, value = false) {
    e.preventDefault();
    if (value) {
      var profile = this.state.profile;
      if (!profile[name]) {
        profile[name] = [];
      }
      profile[name].push(value);
      this.setState({profile: profile});
    } else {
      if (this.state.listAddValue[name]) {
        var profile = this.state.profile;
        var listAddValue = this.state.listAddValue;
        profile[name].push(this.state.listAddValue[name]);
        this.state.listAddValue[name] = "";
        this.setState({profile: profile, listAddValue: listAddValue});
      }
    }
  }

  changeEltConfirm(e, name) {
    var listEltConfirm = this.state.listEltConfirm;
    listEltConfirm[name] = e.target.value;
    this.setState({listEltConfirm: listEltConfirm});
  }

  changeTextArea(e, name, list) {
    var profile = this.state.profile;
    if (list) {
      profile[name] = e.target.value.split("\n");
    } else {
      profile[name] = e.target.value;
    }
    this.setState({profile: profile});
  }

  uploadFile(e, name, list) {
    var profile = this.state.profile;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      if (list) {
        if (!profile[name]) {
          profile[name] = [];
        }
        profile[name].push((file.name + "/" + btoa(ev2.target.result)));
      } else {
        profile[name] = file.name + "/" + btoa(ev2.target.result);
      }
      this.setState({profile: profile});
    };
    fr.readAsText(file);
  }
  
  saveProfile(e) {
    apiManager.glewlwydRequest("/profile", "PUT", this.state.profile)
    .then((res) => {
      messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("profile.save-profile-success")});
    })
    .fail((error) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.save-profile-error")});
    });
  }
  
  editElt(pattern, elt, key) {
    var labelJsx, inputJsx, listJsx = [];
    if ((elt !== undefined || pattern.type === "password" || pattern.forceShow) && pattern["profile-read"]) {
      var validInput = "";
      var errorJsx = "";
      if (this.state.listError[pattern.name]) {
        validInput = " is-invalid";
        errorJsx = <span className="error-input">{i18next.t(this.state.listError[pattern.name])}</span>
      }
      labelJsx = <label htmlFor={"modal-edit-" + pattern.name}>{i18next.t(pattern.label)}</label>;
      if (pattern.list) {
        if (!elt) {
          elt = [];
        }
        if (!pattern.listElements) {
          if (pattern.type === "textarea") {
            inputJsx = <textarea className={"form-control" + validInput} onChange={(e) => this.changeTextArea(e, pattern.name, true)} value={elt.join("\n")} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}></textarea>
          } else if (pattern.type === "file") {
            if (pattern["profile-write"] || this.state.add) {
              inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name, true)} />
            } else {
              inputJsx = <input type="file" disabled={true} className="form-control" />
            }
          } else {
            if (pattern["profile-write"]) {
              inputJsx = <div className="input-group">
                <input type="text" 
                       className={"form-control" + validInput} 
                       id={"modal-edit-" + pattern.name} 
                       placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} 
                       onChange={(e) => this.changeListAddElt(e, pattern.name)} 
                       value={this.state.listAddValue[pattern.name]}/>
                <div className="input-group-append">
                  <button className="btn btn-outline-secondary" type="button" onClick={(e) => this.AddListElt(e, pattern.name)} title={i18next.t("modal.list-add-title")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
              </div>
            }
          }
        } else {
          var listElements = [];
          pattern.listElements.forEach((element, index) => {
            listElements.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.AddListElt(e, pattern.name, element)}>{element}</a>);
          });
          inputJsx = <div className="dropdown">
            <button className="btn btn-secondary btn-sm dropdown-toggle" type="button" id={"modal-edit-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i className="fas fa-plus"></i>
            </button>
            <div className="dropdown-menu" aria-labelledby={"modal-edit-" + pattern.name}>
              {listElements}
            </div>
          </div>
        }
        elt.forEach((val, index) => {
          var displayVal = val;
          if (pattern.type === "file") {
            displayVal = val.substring(0, val.indexOf("/"));
          }
          if (pattern.type !== "textarea") {
            if (pattern["profile-write"] !== true && !this.state.add) {
              listJsx.push(<span className="badge badge-primary btn-icon-right" key={index}>
                             {displayVal}
                           </span>);
            } else {
              listJsx.push(<a href="#" 
                              onClick={(e) => this.deleteListElt(e, pattern.name, index)} 
                              key={index}>
                             <span className="badge badge-primary btn-icon-right">
                              {displayVal}
                              <span className="badge badge-light btn-icon-right">
                                <i className="fas fa-times"></i>
                              </span>
                            </span>
                          </a>);
            }
          }
        });
      } else if (pattern.type === "boolean") {
        if (pattern["profile-write"] !== true && !this.state.add) {
          inputJsx = <input disabled={true} type="checkbox" className="form-control" id={"modal-edit-" + pattern.name} checked={elt} />
        } else {
          inputJsx = <input type="checkbox" className={"form-control" + validInput} id={"modal-edit-" + pattern.name} onChange={(e) => this.toggleBooleanElt(e, pattern.name)} checked={elt} />
        }
      } else if (pattern.type === "textarea") {
        if (pattern["profile-write"] !== true && !this.state.add) {
          inputJsx = <textarea className="form-control" disabled={true} value={elt||""}></textarea>
        } else {
          inputJsx = <textarea className={"form-control" + validInput} 
                               onChange={(e) => this.changeTextArea(e, pattern.name, false)} 
                               value={elt||""} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}>
                     </textarea>
        }
      } else if (pattern.type === "file") {
        if (elt) {
          listJsx.push(<a href="#" key={0} onClick={(e) => this.deleteFile(e, pattern.name)}>
                         <span className="badge badge-primary">
                            {elt.substring(0, elt.indexOf("/"))}
                            <span className="badge badge-light btn-icon-right">
                              <i className="fas fa-times"></i>
                            </span>
                          </span>
                        </a>);
        }
        if (pattern["profile-write"] || this.state.add) {
          inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name)} />
        } else {
          inputJsx = <input type="file" disabled={true} className="form-control" />
        }
      } else {
        if (pattern["profile-write"] !== true && !this.state.add) {
          inputJsx = <input disabled={true} 
                            type={(pattern.type||"text")} 
                            className={"form-control" + validInput} 
                            id={"modal-edit-" + pattern.name} 
                            placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} 
                            value={elt}/>
        } else {
          if (pattern.type === "password") {
            inputJsx = 
              <div>
                <input type="password" 
                       className={"form-control" + validInput} 
                       id={"modal-edit-" + pattern.name} 
                       placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} 
                       onChange={(e) => this.changeElt(e, pattern.name)} value={elt||""}/>
                 <input type="password" 
                        className={"form-control" + validInput} 
                        id={"modal-edit-confirm" + pattern.name} 
                        placeholder={i18next.t(pattern.placeholderConfirm)} 
                        value={this.state.listEltConfirm[pattern.name]||""} 
                        onChange={(e) => this.changeEltConfirm(e, pattern.name)} />
              </div>
          } else {
            inputJsx = <input type={(pattern.type||"text")} 
                              className={"form-control" + validInput} 
                              id={"modal-edit-" + pattern.name} 
                              placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} 
                              value={elt} onChange={(e) => this.changeElt(e, pattern.name)} />
          }
        }
      }
    }
    return (
    <div className="form-group" key={key}>
      {labelJsx}
      {inputJsx}
      <div>{listJsx}</div>
      {errorJsx}
    </div>);
  }

  render() {
    var editLines = [];
    if (this.state.pattern && this.state.profile) {
      this.state.pattern.forEach((pat, index) => {
        var line = this.editElt(pat, this.state.profile[pat.name], index);
        if (line) {
          editLines.push(line);
        }
      });
    }
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.hello", {name: (this.state.profile.name || this.state.profile.username)})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <form className="needs-validation" noValidate>
              {editLines}
            </form>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12 text-right">
            <button type="button" className="btn btn-primary" onClick={(e) => this.saveProfile(e)} disabled={!this.state.profile}>{i18next.t("profile.save")}</button>
          </div>
        </div>
      </div>
    );
  }
}

export default User;
