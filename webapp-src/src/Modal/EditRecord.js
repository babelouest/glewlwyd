import React, { Component } from 'react';

class EditRecord extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      pattern: props.pattern,
      source: props.source,
      data: props.data,
      cb: props.callback,
      validateCb: props.validateCallback,
      profile: props.profile,
      add: props.add,
      listAddValue: this.initListAdd(props.pattern),
      listEltConfirm: this.initListConfirm(props.pattern),
      listError: {}
    }

    this.closeModal = this.closeModal.bind(this);
    this.changeSource = this.changeSource.bind(this);
    this.editElt = this.editElt.bind(this);
    this.changeElt = this.changeElt.bind(this);
    this.toggleBooleanElt = this.toggleBooleanElt.bind(this);
    this.deleteListElt = this.deleteListElt.bind(this);
    this.createData = this.createData.bind(this);
    this.changeListAddElt = this.changeListAddElt.bind(this);
    this.AddListElt = this.AddListElt.bind(this);
    this.initListAdd = this.initListAdd.bind(this);
    this.initListConfirm = this.initListConfirm.bind(this);
    this.changeEltConfirm = this.changeEltConfirm.bind(this);
    this.changeTextArea = this.changeTextArea.bind(this);
    this.uploadFile = this.uploadFile.bind(this);

    if (this.state.add) {
      this.createData();
    }
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      pattern: nextProps.pattern,
      source: nextProps.source,
      data: nextProps.data,
      cb: nextProps.callback,
      validateCb: nextProps.validateCallback,
      profile: nextProps.profile,
      add: nextProps.add,
      listAddValue: this.initListAdd(nextProps.pattern),
      listEltConfirm: this.initListConfirm(nextProps.pattern),
      listError: {}
    }, () => {
      if (nextProps.add) {
        this.createData();
      }
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
      if (result) {
        if (this.state.validateCb) {
          this.state.validateCb(this.state.data, this.state.listEltConfirm, this.state.add, (res, data) => {
            if (res) {
              this.state.cb(result, this.state.data);
            } else {
              this.setState({listError: data});
            }
          });
        } else {
          this.state.cb(result, this.state.data);
        }
      } else {
        this.state.cb(result, {});
      }
    }
  }
  
  changeSource(e, source) {
    var data = this.state.data;
    data.source = source;
    this.setState({data: data});
  }

  editElt(pattern, elt, key) {
    var labelJsx, inputJsx, listJsx = [];
    if (elt !== undefined || pattern.type === "password" || pattern.forceShow) {
      if (!this.state.profile || pattern.profile) {
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
              if (pattern.edit || this.state.add) {
                inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name, true)} />
              } else {
                inputJsx = <input type="file" disabled="true" className="form-control" />
              }
            } else {
              inputJsx = <div className="input-group">
                <input type="text" className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} onChange={(e) => this.changeListAddElt(e, pattern.name)} value={this.state.listAddValue[pattern.name]}/>
                <div className="input-group-append">
                  <button className="btn btn-outline-secondary" type="button" onClick={(e) => this.AddListElt(e, pattern.name)} title={i18next.t("modal.list-add-title")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
              </div>
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
            if (pattern.edit === false && !this.state.add) {
              listJsx.push(<span className="badge badge-primary" key={index}>{displayVal}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span>);
            } else {
              listJsx.push(<a href="#" onClick={(e) => this.deleteListElt(e, pattern.name, index)} key={index}><span className="badge badge-primary">{displayVal}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
            }
          });
        } else if (pattern.type === "boolean") {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <input disabled="true" type="checkbox" className="form-control" id={"modal-edit-" + pattern.name} checked={elt} />
          } else {
            inputJsx = <input type="checkbox" className={"form-control" + validInput} id={"modal-edit-" + pattern.name} onChange={(e) => this.toggleBooleanElt(e, pattern.name)} checked={elt} />
          }
        } else if (pattern.type === "textarea") {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <textarea className="form-control" disabled="true" value={elt||""}></textarea>
          } else {
            inputJsx = <textarea className={"form-control" + validInput} onChange={(e) => this.changeTextArea(e, pattern.name, false)} value={elt||""} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""}></textarea>
          }
        } else if (pattern.type === "file") {
          if (elt) {
            listJsx.push(<a href="#" key={0} onClick={(e) => this.deleteFile(e, pattern.name)}><span className="badge badge-primary">{elt.substring(0, elt.indexOf("/"))}<span className="badge badge-light btn-icon-right"><i className="fas fa-times"></i></span></span></a>);
          }
          if (pattern.edit || this.state.add) {
            inputJsx = <input type="file" className={"form-control" + validInput} onChange={(e) => this.uploadFile(e, pattern.name)} />
          } else {
            inputJsx = <input type="file" disabled="true" className="form-control" />
          }
        } else {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <input disabled="true" type={(pattern.type||"text")} className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt}/>
          } else {
            if (pattern.type === "password") {
              inputJsx = <div><input type="password" className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} onChange={(e) => this.changeElt(e, pattern.name)} value={elt||""}/><input type="password" className={"form-control" + validInput} id={"modal-edit-confirm" + pattern.name} placeholder={i18next.t(pattern.placeholderConfirm)} value={this.state.listEltConfirm[pattern.name]||""} onChange={(e) => this.changeEltConfirm(e, pattern.name)} /></div>
            } else {
              inputJsx = <input type={(pattern.type||"text")} className={"form-control" + validInput} id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt} onChange={(e) => this.changeElt(e, pattern.name)} />
            }
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

  deleteListElt(e, name, index) {
    var data = this.state.data;
    if (data[name]) {
      data[name].splice(index, 1);
      this.setState({data: data});
    }
  }

  changeElt(e, name) {
    var data = this.state.data;
    data[name] = e.target.value;
    this.setState({data: data});
  }

  toggleBooleanElt(e, name) {
    var data = this.state.data;
    data[name] = !data[name];
    this.setState({data: data});
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

  changeListAddElt(e, name) {
    var listAddValue = this.state.listAddValue;
    listAddValue[name] = e.target.value;
    this.setState({listAddValue: listAddValue});
  }

  AddListElt(e, name, value = false) {
    e.preventDefault();
    if (value) {
      var data = this.state.data;
      if (!data[name]) {
        data[name] = [];
      }
      data[name].push(value);
      this.setState({data: data});
    } else {
      if (this.state.listAddValue[name]) {
        var data = this.state.data;
        var listAddValue = this.state.listAddValue;
        data[name].push(this.state.listAddValue[name]);
        this.state.listAddValue[name] = "";
        this.setState({data: data, listAddValue: listAddValue});
      }
    }
  }

  initListAdd(patternList) {
    var listAddValue = {};
    patternList.forEach((pat) => {
      if (pat.list) {
        listAddValue[pat.name] = "";
      }
    });
    return listAddValue;
  }

  initListConfirm(patternList) {
    var listEltConfirm = {};
    patternList.forEach((pat) => {
      if (pat.confirm) {
        listEltConfirm[pat.name] = "";
      }
    });
    return listEltConfirm;
  }

  changeEltConfirm(e, name) {
    var listEltConfirm = this.state.listEltConfirm;
    listEltConfirm[name] = e.target.value;
    this.setState({listEltConfirm: listEltConfirm});
  }

  changeTextArea(e, name, list) {
    var data = this.state.data;
    if (list) {
      data[name] = e.target.value.split("\n");
    } else {
      data[name] = e.target.value;
    }
    this.setState({data: data});
  }

  uploadFile(e, name, list) {
    var data = this.state.data;
    var file = e.target.files[0];
    var fr = new FileReader();
    fr.onload = (ev2) => {
      if (list) {
        if (!data[name]) {
          data[name] = [];
        }
        data[name].push((file.name + "/" + btoa(ev2.target.result)));
      } else {
        data[name] = file.name + "/" + btoa(ev2.target.result);
      }
      this.setState({data: data});
    };
    fr.readAsText(file);
  }
  
	render() {
    var editLines = [], sourceLine = [], curSource = false;
    this.state.pattern.forEach((pat, index) => {
      var line = this.editElt(pat, this.state.data[pat.name], index);
      if (line) {
        editLines.push(line);
      }
    });
    this.state.source.forEach((source, index) => {
      if ((!curSource && !source.readonly) || source.name === this.state.data.source) {
        curSource = source.display_name;
      }
      sourceLine.push(<a className="dropdown-item" key={index} href="#" onClick={(e) => this.changeSource(e, source.name)}>{source.display_name}</a>);
    });
    var sourceJsx = <div className="form-group">
      <label htmlFor="modal-source">{i18next.t("admin.source")}</label>
      <div className="dropdown">
        <button className="btn btn-secondary btn-sm dropdown-toggle" type="button" id="modal-source" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
         {curSource||i18next.t("admin.source-dropdown")}
        </button>
        <div className="dropdown-menu" aria-labelledby="modal-source">
          {sourceLine}
        </div>
      </div>
    </div>
		return (
    <div className="modal fade" id="editRecordModal" tabIndex="-1" role="dialog" aria-labelledby="editRecordModalLabel" aria-hidden="true">
      <div className="modal-dialog modal-lg" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="editRecordModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            <form className="needs-validation" noValidate>
              {sourceJsx}
              {editLines}
            </form>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default EditRecord;
