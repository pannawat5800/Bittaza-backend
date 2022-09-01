export class Context {
    private uid: string
    constructor(uid: string) {
        this.uid = uid
    }

    getUid(): string {
        return this.uid
    }
}